// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use pretty_hex::pretty_hex;

use dominion_parser::body::{RecordData, RecordPreamble, ResourceRecord};
use dominion_parser::header::{AuthenticData, QueryResponse, RecursionAvailable};
use dominion_parser::DnsPacket;

const REQ: &[u8; 33] = include_bytes!("../assets/dns_request.bin");
const RES: &[u8; 49] = include_bytes!("../assets/dns_response.bin");

fn main() {
    let mut res = DnsPacket::try_from(&REQ[..]).unwrap();

    // Change some flags
    res.header.flags.qr = QueryResponse::Response;
    res.header.flags.ra = RecursionAvailable::Available;
    res.header.flags.ad = AuthenticData::NotAuthentic;

    // Add answer
    let preamble = RecordPreamble {
        name: res.questions[0].name.clone(),
        rrtype: res.questions[0]
            .qtype
            .try_into()
            .expect("QType is not a valid Type"),
        class: res.questions[0].class,
        ttl: 300,
        rdlen: 4,
    };
    let data = RecordData::A("204.74.99.100".parse().unwrap());
    let answer = ResourceRecord { preamble, data };
    res.header.answers = 1;
    res.answers.push(answer);

    let res = Vec::<u8>::from(&res);

    println!("=================== My Response ===================");
    println!("{}\n", pretty_hex(&res));

    println!("=================== Compressed Response ===================");
    println!("{}\n", pretty_hex(RES));
}
