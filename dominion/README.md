
# Dominion

A crate to implement DNS [Server]s and clients.

## Server

```rust
use dominion::{Server, ServerService, DnsPacket};
use std::net::SocketAddr;

struct Echo;

impl ServerService for Echo {
   fn run<'a>(&self, _client: SocketAddr, question: DnsPacket<'a>) -> Option<DnsPacket<'a>> { Some(question) }
}

Server::default()
       .bind("127.0.0.1:5353".parse().unwrap())
       .unwrap()
       .serve(Echo);
```

## Client

