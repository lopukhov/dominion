// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

#![forbid(unsafe_code)]
#![warn(rust_2018_idioms, missing_debug_implementations)]

use argh::FromArgs;
use dominion::{DnsPacket, Name, QType, Server, ServerService};
use owo_colors::OwoColorize;
use std::net::{IpAddr, SocketAddr};

mod a;

#[derive(Clone, Debug, FromArgs)]
/// Receive DNS messages from the world
struct ChatArgs {
    /// number of threads in the thread pool
    #[argh(option, short = 't', default = "num_cpus::get()")]
    threads: usize,
    /// UDP port to listen to
    #[argh(option, short = 'p', default = "54")]
    port: u16,
    /// ip to listen to
    #[argh(option, short = 'i', default = "any_ip()")]
    ip: IpAddr,
    /// domain name to use as a filter
    #[argh(option, short = 'd')]
    domain: Option<String>,
}

fn main() {
    let args: ChatArgs = argh::from_env();

    let name = match args.domain {
        Some(domain) => domain,
        None => "".to_string(),
    };

    let name = match Name::try_from(name.as_ref()) {
        Ok(name) => name,
        Err(_) => {
            eprintln!(
                "{}: could not parse the domain name because some label is too big.",
                "ERROR".red()
            );
            std::process::exit(1)
        }
    };

    let chat = Chat::new(name);

    let server = match Server::default()
        .threads(args.threads)
        .bind((args.ip, args.port).into())
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

struct Chat<'a>(Name<'a>);

impl<'a> Chat<'a> {
    fn new(name: Name<'a>) -> Self {
        Chat(name)
    }
}

impl ServerService for Chat<'_> {
    fn run<'b>(&self, client: SocketAddr, question: DnsPacket<'b>) -> Option<DnsPacket<'b>> {
        if question.header.questions > 0 {
            match question.questions[0].qtype {
                QType::A => Some(a::response(client, question, &self.0)),
                _ => Some(refused(question.header.id)),
            }
        } else {
            Some(refused(question.header.id))
        }
    }
}

fn any_ip() -> IpAddr {
    "0.0.0.0".parse().unwrap()
}

fn refused(id: u16) -> DnsPacket<'static> {
    use dominion::*;

    let flags = Flags {
        qr: QueryResponse::Response,
        opcode: OpCode::Query,
        aa: AuthoritativeAnswer::Authoritative,
        tc: TrunCation::NotTruncated,
        rd: RecursionDesired::NotDesired,
        ra: RecursionAvailable::NotAvailable,
        z: Zero::Zero,
        ad: AuthenticData::NotAuthentic,
        cd: CheckingDisabled::Disabled,
        rcode: ResponseCode::Refused,
    };

    let header = DnsHeader {
        id,
        flags,
        questions: 0,
        answers: 0,
        authority: 0,
        additional: 0,
    };
    DnsPacket {
        header,
        questions: vec![],
        answers: vec![],
        authority: vec![],
        additional: vec![],
    }
}
