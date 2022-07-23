// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use dominion_parser::DnsPacket;

const REQ: &'static [u8; 33] = include_bytes!("../assets/dns_request.bin");
const RES: &'static [u8; 49] = include_bytes!("../assets/dns_response.bin");

fn main() {
    let packet = DnsPacket::try_from(&REQ[..]).unwrap();
    println!("The request was:");
    println!("{:#?}", packet);

    println!("=========================================================================");

    let packet = DnsPacket::try_from(&RES[..]).unwrap();
    println!("The response was:");
    println!("{:#?}", packet);
}
