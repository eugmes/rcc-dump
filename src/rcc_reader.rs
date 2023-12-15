use std::collections::HashSet;
use std::io::{self, Cursor, Read};
use std::marker::PhantomData;
use std::string::FromUtf16Error;

use bitflags::bitflags;
use chrono::{DateTime, Utc};
use nom::{
    bytes::complete::{tag, take},
    multi::count,
    number,
    sequence::tuple,
    IResult,
};
use thiserror::Error;

bitflags! {
    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct OverallFlags: u32 {
        const Compressed = 0x01;
        const CompressedZstd = 0x04;
    }

    #[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
    pub struct NodeFlags: u16 {
        const Compressed = 0x01;
        const Directory = 0x02;
        const CompressedZstd = 0x04;
    }
}

#[derive(Debug)]
struct RccHeader {
    format_version: u32,
    tree_offset: u32,
    data_offset: u32,
    names_offset: u32,
    overall_flags: Option<OverallFlags>,
}

#[derive(Debug)]
enum NodeData {
    Directory {
        child_count: u32,
        first_child_offset: u32,
    },
    File {
        territory: u16,
        language: u16,
        data_offset: u32,
    },
}

#[derive(Debug)]
struct RccFileInfo {
    name_offset: u32,
    flags: NodeFlags,
    node_data: NodeData,
    last_modified: Option<u64>,
}

#[derive(Debug)]
struct RccName {
    hash: u32,
    name: String,
}

fn big_u16(input: &[u8]) -> IResult<&[u8], u16> {
    number::complete::u16(number::Endianness::Big)(input)
}

fn big_u32(input: &[u8]) -> IResult<&[u8], u32> {
    number::complete::u32(number::Endianness::Big)(input)
}

fn big_u64(input: &[u8]) -> IResult<&[u8], u64> {
    number::complete::u64(number::Endianness::Big)(input)
}

#[derive(Debug, Clone)]
pub enum ResourceTreeNodeData<'a> {
    Directory {
        children: Vec<ResourceTreeNode<'a>>,
    },
    File {
        territory: u16,
        language: u16,
        raw_data_size: u32,
        data_size: Option<usize>,
    },
}

#[derive(Debug, Clone)]
pub struct ResourceTreeNode<'a> {
    pub name: String,
    pub hash: u32,
    pub last_modified: Option<DateTime<Utc>>,
    pub extra_data: ResourceTreeNodeData<'a>,
    flags: NodeFlags,
    data_offset: Option<u32>,
    _phantom: PhantomData<&'a RccReader<'a>>,
}

#[derive(Debug, Error)]
pub enum RccReaderError {
    #[error("Unsupported format version {0}")]
    UnsupportedFormatVersion(u32),
    #[error("Unknown overall flags: {0:?}")]
    UnknownOverallFlags(OverallFlags),
    #[error("Unknown node flags: {0:?}")]
    UnknownNodeFlags(NodeFlags),
    #[error("Tree offset {tree_offset} is larger than data size {data_len}")]
    InvalidTreeOffset { tree_offset: usize, data_len: usize },
    #[error("Names offset {name_offset} is larger than data size {data_len}")]
    InvalidNameOffset { name_offset: usize, data_len: usize },
    #[error("Data offset {data_offset} is larger than data size {data_len}")]
    InvalidDataOffset { data_offset: usize, data_len: usize },
    #[error("Directory loop detected")]
    DirectoryLoopError,
    #[error("Parse error")]
    ParseError,
    #[error("String decode error")]
    StringDecodeError(#[from] FromUtf16Error),
    #[error("Zstd decode error")]
    ZstdDecodeError(#[from] io::Error),
}

// This has to be implemented separately to avoid leaking lifetime of the source buffer
impl<I> From<nom::Err<nom::error::Error<I>>> for RccReaderError {
    fn from(_value: nom::Err<nom::error::Error<I>>) -> Self {
        RccReaderError::ParseError
    }
}

type Result<T> = std::result::Result<T, RccReaderError>;

#[derive(Debug)]
pub struct RccReader<'a> {
    data: &'a [u8],
    names_offset: usize,
    data_offset: usize,
    file_infos: Vec<RccFileInfo>,
}

impl<'a> RccReader<'a> {
    pub fn new(data: &'a [u8]) -> Result<Self> {
        let (_tail, header) = rcc_header(data)?;

        if let Some(flags) = header.overall_flags {
            let unknown_flags = flags.difference(OverallFlags::all());
            if !unknown_flags.is_empty() {
                Err(RccReaderError::UnknownOverallFlags(flags))?;
            }
        }

        let format_version = header.format_version;
        let tree_offset = header.tree_offset as usize;
        let names_offset = header.names_offset as usize;
        let data_offset = header.data_offset as usize;

        let input = data
            .get(tree_offset..)
            .ok_or(RccReaderError::InvalidTreeOffset {
                tree_offset,
                data_len: data.len(),
            })?;
        let file_infos = rcc_file_infos(format_version, input)?;

        Ok(Self {
            data,
            names_offset,
            data_offset,
            file_infos,
        })
    }

    pub fn read_file_tree(&self) -> Result<ResourceTreeNode> {
        self.read_file_tree_helper(0, &mut HashSet::new())
    }

    pub fn get_data_stream(&self, tree_node: &ResourceTreeNode<'a>) -> Result<Box<dyn Read + 'a>> {
        match tree_node.data_offset {
            Some(offset) => {
                let real_offset = self.data_offset + offset as usize;
                let input =
                    self.data
                        .get(real_offset..)
                        .ok_or(RccReaderError::InvalidNameOffset {
                            name_offset: real_offset,
                            data_len: self.data.len(),
                        })?;
                rcc_data_stream(tree_node.flags, input)
            }
            None => Ok(Box::new(Cursor::new(&[]))),
        }
    }

    fn read_file_tree_helper(
        &self,
        node_index: u32,
        visited_indices: &mut HashSet<u32>,
    ) -> Result<ResourceTreeNode> {
        if visited_indices.contains(&node_index) {
            Err(RccReaderError::DirectoryLoopError)?
        }
        visited_indices.insert(node_index);
        let info = &self
            .file_infos
            .get(node_index as usize)
            .expect("Internal error while indexing file_infos");
        let node_name = self.read_name(info.name_offset)?;
        let name = node_name.name.clone();
        let hash = node_name.hash;

        let last_modified = info.last_modified.and_then(|ts| {
            let secs = (ts / 1000) as i64;
            let msecs = (ts % 1000) as u32;
            let nsecs = msecs * 1_000_000;
            DateTime::from_timestamp(secs, nsecs)
        });

        let (extra_data, data_offset) = match info.node_data {
            NodeData::Directory {
                child_count,
                first_child_offset,
            } => {
                let mut children = Vec::new();
                for child in 0..child_count {
                    let node_index = first_child_offset + child;
                    let child_data = self.read_file_tree_helper(node_index, visited_indices)?;
                    children.push(child_data);
                }
                let extra_data = ResourceTreeNodeData::Directory { children };
                (extra_data, None)
            }
            NodeData::File {
                territory,
                language,
                data_offset,
            } => {
                let (raw_data_size, data_size) = self.get_data_size(info.flags, data_offset)?;
                let extra_data = ResourceTreeNodeData::File {
                    language,
                    territory,
                    raw_data_size,
                    data_size,
                };
                (extra_data, Some(data_offset))
            }
        };

        visited_indices.remove(&node_index);

        let resource_tree_node = ResourceTreeNode {
            name,
            hash,
            last_modified,
            extra_data,
            data_offset,
            flags: info.flags,
            _phantom: PhantomData,
        };
        Ok(resource_tree_node)
    }

    fn get_data_size(&self, flags: NodeFlags, offset: u32) -> Result<(u32, Option<usize>)> {
        let real_offset = self.data_offset + offset as usize;
        let input = self
            .data
            .get(real_offset..)
            .ok_or(RccReaderError::InvalidNameOffset {
                name_offset: real_offset,
                data_len: self.data.len(),
            })?;
        rcc_data_size(flags, input)
    }

    fn read_name(&self, offset: u32) -> Result<RccName> {
        let real_offset = self.names_offset + offset as usize;
        let input = self
            .data
            .get(real_offset..)
            .ok_or(RccReaderError::InvalidDataOffset {
                data_offset: real_offset,
                data_len: self.data.len(),
            })?;
        rcc_name(input)
    }
}

fn rcc_header(input: &[u8]) -> Result<(&[u8], RccHeader)> {
    let (input, _magic) = tag("qres")(input)?;
    let (input, format_version) = big_u32(input)?;
    if format_version > 3 {
        Err(RccReaderError::UnsupportedFormatVersion(format_version))?
    }
    let (input, (tree_offset, data_offset, names_offset)) =
        tuple((big_u32, big_u32, big_u32))(input)?;

    let (input, overall_flags) = if format_version >= 3 {
        let (input, overall_flags) = big_u32(input)?;
        (input, Some(OverallFlags::from_bits_retain(overall_flags)))
    } else {
        (input, None)
    };

    let rcc_header = RccHeader {
        format_version,
        tree_offset,
        data_offset,
        names_offset,
        overall_flags,
    };
    Ok((input, rcc_header))
}

fn rcc_file_info(format_version: u32, input: &[u8]) -> Result<(&[u8], RccFileInfo)> {
    let (input, (name_offset, flags)) = tuple((big_u32, big_u16))(input)?;
    let flags = NodeFlags::from_bits_retain(flags);

    let unknown_flags = flags.difference(NodeFlags::all());
    if !unknown_flags.is_empty() {
        Err(RccReaderError::UnknownNodeFlags(unknown_flags))?;
    }

    let (input, node_data) = if flags.contains(NodeFlags::Directory) {
        let (input, (child_count, first_child_offset)) = tuple((big_u32, big_u32))(input)?;
        let node_data = NodeData::Directory {
            child_count,
            first_child_offset,
        };
        (input, node_data)
    } else {
        let (input, (territory, language, data_offset)) =
            tuple((big_u16, big_u16, big_u32))(input)?;
        let node_data = NodeData::File {
            territory,
            language,
            data_offset,
        };
        (input, node_data)
    };

    let (input, last_modified) = if format_version >= 2 {
        let (input, last_modified) = big_u64(input)?;
        (input, Some(last_modified))
    } else {
        (input, None)
    };

    let rcc_file_info = RccFileInfo {
        name_offset,
        flags,
        node_data,
        last_modified,
    };
    Ok((input, rcc_file_info))
}

fn rcc_file_infos(format_version: u32, mut input: &[u8]) -> Result<Vec<RccFileInfo>> {
    let mut file_count = 0usize;
    let mut max_file_index = 1usize;
    let mut file_infos = vec![];

    while max_file_index >= file_count {
        let (tail, file_info) = rcc_file_info(format_version, input)?;
        input = tail;
        if let NodeData::Directory {
            child_count,
            first_child_offset,
        } = file_info.node_data
        {
            if child_count > 0 {
                max_file_index =
                    max_file_index.max((child_count - 1) as usize + first_child_offset as usize);
            }
        }
        file_infos.push(file_info);
        file_count += 1;
    }

    Ok(file_infos)
}

fn rcc_name(input: &[u8]) -> Result<RccName> {
    let (input, (size, hash)) = tuple((big_u16, big_u32))(input)?;
    let (_input, chars) = count(big_u16, size as usize)(input)?;
    let name = String::from_utf16(&chars)?;
    Ok(RccName { hash, name })
}

fn rcc_data_stream<'a>(flags: NodeFlags, input: &'a [u8]) -> Result<Box<dyn Read + 'a>> {
    let (input, raw_data_size) = big_u32(input)?;
    let (_input, raw_data) = take(raw_data_size)(input)?;

    let stream = if raw_data_size > 0 && flags.contains(NodeFlags::CompressedZstd) {
        Box::new(zstd::Decoder::new(raw_data)?) as Box<dyn Read + 'a>
    } else if raw_data_size > 0 && flags.contains(NodeFlags::Compressed) {
        let (raw_data, expected_size) = big_u32(raw_data)?;
        let expected_size = expected_size as usize;
        if expected_size == 0 {
            Box::new(Cursor::new(&[]))
        } else {
            Box::new(inflate::DeflateDecoder::from_zlib(raw_data)) as Box<dyn Read + 'a>
        }
    } else {
        Box::new(Cursor::new(raw_data))
    };
    Ok(stream)
}

fn rcc_data_size(flags: NodeFlags, input: &[u8]) -> Result<(u32, Option<usize>)> {
    let (input, raw_data_size) = big_u32(input)?;
    let (_input, raw_data) = take(raw_data_size)(input)?;

    let data_size = if raw_data_size == 0 {
        Some(0)
    } else if flags.contains(NodeFlags::CompressedZstd) {
        zstd::bulk::Decompressor::upper_bound(raw_data)
    } else if flags.contains(NodeFlags::Compressed) {
        let (_raw_data, expected_size) = big_u32(raw_data)?;
        Some(expected_size as usize)
    } else {
        Some(raw_data_size as usize)
    };
    Ok((raw_data_size, data_size))
}
