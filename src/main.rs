use std::fs;
use std::path::PathBuf;

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
    /// Maximum amount of data to show
    max_data_size: usize,
}

/// Format the byte array into hexdump format.
fn format_data(data: &[u8]) -> impl Iterator<Item = String> + '_ {
    data.chunks(16).map(|chunk| {
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
        format!("│{:<47}│{:<16}│", hex_data.join(" "), ascii_dump)
    })
}

fn print_node(tree_node: &ResourceTreeNode, include_data: bool, max_data_size: usize) {
    match &tree_node.extra_data {
        ResourceTreeNodeData::Directory { children: _ } => println!("{}", tree_node.name),
        ResourceTreeNodeData::File {
            territory,
            language,
            data,
        } => {
            if include_data {
                println!(
                    "{} [territory={}, language={}, size={}{}]",
                    tree_node.name,
                    territory,
                    language,
                    data.len(),
                    if data.len() > max_data_size {
                        ", incomplete"
                    } else {
                        ""
                    }
                );
                format_data(data.get(..max_data_size).unwrap_or(data))
                    .for_each(|line| println!("{}", line))
            } else {
                println!(
                    "{} [territory={}, language={}]",
                    tree_node.name, territory, language
                )
            }
        }
    }
}

fn print_tree_helper(
    prefix: &str,
    tree_node: &ResourceTreeNode,
    include_data: bool,
    max_data_size: usize,
) {
    const OTHER_CHILD: &str = "│   "; // prefix: pipe
    const OTHER_ENTRY: &str = "├── "; // connector: tee
    const FINAL_CHILD: &str = "    "; // prefix: no more siblings
    const FINAL_ENTRY: &str = "└── "; // connector: elbow

    if let ResourceTreeNodeData::Directory { children } = &tree_node.extra_data {
        let mut count = children.len();

        for child in children {
            count -= 1;
            let connector = if count == 0 { FINAL_ENTRY } else { OTHER_ENTRY };
            print!("{}{}", prefix, connector);
            print_node(child, include_data, max_data_size);

            let new_prefix = format!(
                "{}{}",
                prefix,
                if count == 0 { FINAL_CHILD } else { OTHER_CHILD }
            );
            print_tree_helper(&new_prefix, child, include_data, max_data_size)
        }
    }
}

/// Print the file tree to stdout starting from the given node.
fn print_tree(tree_root: &ResourceTreeNode, include_data: bool, max_data_size: usize) {
    print_node(tree_root, include_data, max_data_size);
    print_tree_helper("", tree_root, include_data, max_data_size)
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();
    let data = fs::read(args.rcc_path).context("Failed to read the file")?;

    let reader = RccReader::new(&data).context("Failed to create RCC reader")?;
    let tree_root = reader
        .read_file_tree(args.include_data)
        .context("Failed to read file tree")?;
    print_tree(&tree_root, args.include_data, args.max_data_size);

    Ok(())
}
