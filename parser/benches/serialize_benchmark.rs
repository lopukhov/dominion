// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dominion_parser::DnsPacket;

use pprof::criterion::{Output, PProfProfiler};

const REQ: &[u8; 33] = include_bytes!("../assets/dns_request.bin");
const RES: &[u8; 49] = include_bytes!("../assets/dns_response.bin");

pub fn serialize_request(c: &mut Criterion) {
    let req = DnsPacket::try_from(&REQ[..]).unwrap();
    let req = &req;
    c.bench_function("serialize_req", |b| {
        b.iter(|| Vec::<u8>::from(black_box(req)))
    });
}

pub fn serialize_response(c: &mut Criterion) {
    let res = DnsPacket::try_from(&RES[..]).unwrap();
    let res = &res;
    c.bench_function("serialize_res", |b| {
        b.iter(move || Vec::<u8>::from(black_box(res)))
    });
}

criterion_group!(
    name = serialize;
    config = Criterion::default()
            .with_profiler(
                PProfProfiler::new(100, Output::Flamegraph(None))
            );
    targets = serialize_request, serialize_response
);
criterion_main!(serialize);
