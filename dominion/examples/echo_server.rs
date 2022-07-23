// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dominion::{DnsPacket, Server, ServerService};

struct Echo;

impl ServerService for Echo {
    fn run<'a>(&self, question: DnsPacket<'a>) -> DnsPacket<'a> {
        question
    }
}

fn main() {
    Server::default()
        .bind("127.0.0.1:5454".parse().unwrap())
        .unwrap()
        .serve(Echo)
        .unwrap();
}
