
# Dominion

A crate to implement DNS [Server]s and clients.

## Server

```rust
use dominion::{Server, ServerService, DnsPacket};

struct Echo;

impl ServerService for Echo {
   fn run<'a>(&self, question: DnsPacket<'a>) -> DnsPacket<'a> { question }
}

Server::default()
       .bind("127.0.0.1:5454".parse().unwrap())
       .unwrap()
       .serve(Echo);
```

## Client
