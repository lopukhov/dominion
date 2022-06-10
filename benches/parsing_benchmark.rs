use criterion::{black_box, criterion_group, criterion_main, Criterion};
use dominion_parser::DnsPacket;

use pprof::criterion::{Output, PProfProfiler};

const REQ: &'static [u8; 33] = include_bytes!("../assets/dns_request.bin");
const RES: &'static [u8; 49] = include_bytes!("../assets/dns_response.bin");

pub fn parse_request(c: &mut Criterion) {
    c.bench_function("parse_req", |b| {
        b.iter(|| DnsPacket::try_from(black_box(&REQ[..])).unwrap())
    });
}

pub fn parse_response(c: &mut Criterion) {
    c.bench_function("parse_res", |b| {
        b.iter(|| DnsPacket::try_from(black_box(&RES[..])).unwrap())
    });
}

criterion_group!(
    name = benches;
    config = Criterion::default()
            .with_profiler(
                PProfProfiler::new(100, Output::Flamegraph(None))
            );
    targets = parse_request, parse_response
);
criterion_main!(benches);