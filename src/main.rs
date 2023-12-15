use std::path::PathBuf;
use std::{fs, io::Read};

use anyhow::Context;
use clap::Parser;
use rcc_reader::ResourceTreeNode;

use crate::rcc_reader::{RccReader, ResourceTreeNodeData};

mod rcc_reader;

#[derive(Debug, Parser)]
#[command(author, version, about)]
/// Validate and print Qt RCC file content.
struct Args {
    /// Resource file path
    rcc_path: PathBuf,
    /// Read the file data
    #[arg(short = 'd', long, action)]
    include_data: bool,
    #[arg(short, long, default_value = "80")]
    /// Maximum amount of data to show (will be rounded up to multiple of 16)
    max_data_size: usize,
}

/// Format the data into hexdump format.
fn format_data(stream: &mut dyn Read, mut max_data_size: usize) -> anyhow::Result<()> {
    let mut buf = [0u8; 16];
    while max_data_size > 0 {
        let chunk_size = stream.read(&mut buf)?;
        if chunk_size == 0 {
            return Ok(());
        };
        max_data_size -= chunk_size.min(max_data_size);

        let chunk = &buf[..chunk_size];
        let hex_data: Vec<_> = chunk.iter().map(|b| format!("{:02x}", b)).collect();
        let ascii_dump: String = chunk
            .iter()
            .map(|b| {
                if (*b >= 0x20) && (*b < 0x7f) {
                    *b as char
                } else {
                    '.'
                }
            })
            .collect();
        println!("│{:<47}│{:<16}│", hex_data.join(" "), ascii_dump);
        if chunk_size < buf.len() {
            return Ok(());
        }
    }
    println!("│{:<47}│{:<16}│", "...", "...");
    Ok(())
}

fn print_node(
    reader: &RccReader,
    tree_node: &ResourceTreeNode,
    include_data: bool,
    max_data_size: usize,
) -> anyhow::Result<()> {
    match &tree_node.extra_data {
        ResourceTreeNodeData::Directory { children: _ } => println!("{}", tree_node.name),
        ResourceTreeNodeData::File {
            territory,
            language,
            raw_data_size,
            data_size,
        } => {
            println!(
                "{} [territory={}, language={}, raw_size={}, size={}]",
                tree_node.name,
                territory,
                language,
                raw_data_size,
                data_size.map_or("???".to_owned(), |sz| sz.to_string())
            );
            if include_data {
                format_data(reader.get_data_stream(tree_node)?.as_mut(), max_data_size)?;
            };
        }
    }
    Ok(())
}

fn print_tree_helper(
    reader: &RccReader,
    prefix: &str,
    tree_node: &ResourceTreeNode,
    include_data: bool,
    max_data_size: usize,
) -> anyhow::Result<()> {
    const OTHER_CHILD: &str = "│   ";
    const OTHER_ENTRY: &str = "├── ";
    const FINAL_CHILD: &str = "    ";
    const FINAL_ENTRY: &str = "└── ";

    if let ResourceTreeNodeData::Directory { children } = &tree_node.extra_data {
        let mut count = children.len();

        for child in children {
            count -= 1;
            let connector = if count == 0 { FINAL_ENTRY } else { OTHER_ENTRY };
            print!("{}{}", prefix, connector);
            print_node(reader, child, include_data, max_data_size)?;

            let new_prefix = format!(
                "{}{}",
                prefix,
                if count == 0 { FINAL_CHILD } else { OTHER_CHILD }
            );
            print_tree_helper(reader, &new_prefix, child, include_data, max_data_size)?
        }
    }
    Ok(())
}

/// Print the file tree to stdout starting from the given node.
fn print_tree(
    reader: &RccReader,
    tree_root: &ResourceTreeNode,
    include_data: bool,
    max_data_size: usize,
) -> anyhow::Result<()> {
    print_node(reader, tree_root, include_data, max_data_size)?;
    print_tree_helper(reader, "", tree_root, include_data, max_data_size)
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let data = fs::read(args.rcc_path).context("Failed to read the file")?;

    let reader = RccReader::new(&data).context("Failed to create RCC reader")?;
    let tree_root = reader
        .read_file_tree()
        .context("Failed to read file tree")?;
    print_tree(&reader, &tree_root, args.include_data, args.max_data_size)
}
