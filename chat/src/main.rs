// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_debug_implementations)]

use dominion_chat::Xor;

use argh::FromArgs;
use dominion::{Name, Server};
use owo_colors::OwoColorize;
use serde::Deserialize;
use std::collections::BTreeMap;
use std::error::Error;
use std::net::IpAddr;

const CONFIG_FILE: &str = "./configuration.toml";

/// Configuration for the DNS chat
struct Configuration {
    ip: IpAddr,
    port: u16,
    domain: String,
    threads: usize,
    xor: Option<Xor>,
    files: Option<BTreeMap<String, String>>,
}

#[derive(Clone, Debug, FromArgs)]
/// Receive DNS messages from the world
struct ChatArgs {
    /// number of threads in the thread pool
    #[argh(option, short = 't')]
    threads: Option<usize>,
    /// UDP port to listen to
    #[argh(option, short = 'p')]
    port: Option<u16>,
    /// ip to listen to
    #[argh(option, short = 'i')]
    ip: Option<IpAddr>,
    /// domain name to use as a filter
    #[argh(option, short = 'd')]
    domain: Option<String>,
}

#[derive(Debug, Deserialize)]
/// Configuration from file
struct RawConfig {
    threads: Option<usize>,
    ip: Option<IpAddr>,
    port: Option<u16>,
    domain: Option<String>,
    xor: Option<Xor>,
    files: Option<BTreeMap<String, String>>,
}

fn main() {
    let config = configuration();

    let name = match Name::try_from(config.domain.as_ref()) {
        Ok(name) => name,
        Err(_) => {
            eprintln!(
                "{}: could not parse the domain name because some label is too big.",
                "ERROR".red()
            );
            std::process::exit(1)
        }
    };

    let chat = dominion_chat::Chat::new(name, config.xor, config.files);

    let server = match Server::default()
        .threads(config.threads)
        .bind((config.ip, config.port).into())
    {
        Ok(server) => server,
        Err(e) => {
            eprintln!(
                "{}: Could not bind to the specified interface or port.\n\n{}",
                "ERROR".red(),
                e
            );
            std::process::exit(1)
        }
    };
    server.serve(chat)
}

macro_rules! select_cfg {
    ($arg:expr, $conf:expr, $default:expr) => {
        match ($arg, $conf) {
            (Some(a), _) => a,
            (None, Some(c)) => c,
            (None, None) => $default,
        }
    };
}

fn configuration() -> Configuration {
    let args: ChatArgs = argh::from_env();
    let config = match read_config() {
        Ok(cfg) => cfg,
        Err(_) => RawConfig {
            threads: None,
            ip: None,
            port: None,
            domain: None,
            xor: None,
            files: None,
        },
    };

    let ip = select_cfg!(args.ip, config.ip, "0.0.0.0".parse().unwrap());
    let port = select_cfg!(args.port, config.port, 53);
    let domain = select_cfg!(args.domain, config.domain, String::new());
    let threads = select_cfg!(args.threads, config.threads, num_cpus::get());

    Configuration {
        ip,
        port,
        domain,
        threads,
        xor: config.xor,
        files: config.files,
    }
}

fn read_config() -> Result<RawConfig, Box<dyn Error>> {
    let config = std::fs::read_to_string(CONFIG_FILE)?;
    let config = toml::from_str(&config)?;
    Ok(config)
}
