# Dominion Parser

DNS parser with a focus on usage of the type system to create a declarative
experience when parsing or serializing DNS packets. It allows parsing and serializing
whole packets or individual elements, like the header or the different questions and
resource records. Not all resource records have been implemented, if some are missing
that are relevant for your use case please open an [issue](https://github.com/lopukhov/dominion/issues).

## Parsing

```rust
use dominion_parser::DnsPacket;
const REQ: &'static [u8; 33] = include_bytes!("../assets/dns_request.bin");
fn main() {
    let packet = DnsPacket::try_from(&REQ[..]).unwrap();
    println!("The request was:");
    println!("{:#?}", packet);
}
```

## Serializing

```rust
use dominion_parser::body::{RecordData, RecordPreamble, ResourceRecord};
use dominion_parser::header::{AuthenticData, QueryResponse, RecursionAvailable};
use dominion_parser::DnsPacket;
const REQ: &'static [u8; 33] = include_bytes!("../assets/dns_request.bin");
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
    println!("{:?}", res);
}
```

