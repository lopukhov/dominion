// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use std::net::SocketAddr;

use dominion::{DnsPacket, Server, ServerService};

struct Echo;

impl ServerService for Echo {
    fn run<'a>(&self, _: SocketAddr, question: DnsPacket<'a>) -> Option<DnsPacket<'a>> {
        Some(question)
    }
}

fn main() {
    Server::default()
        .threads(6)
        .bind("127.0.0.1:5353".parse().unwrap())
        .unwrap()
        .serve(Echo)
}
