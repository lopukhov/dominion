// This Source Code Form is subject to the terms of the Mozilla Public
// License, v. 2.0. If a copy of the MPL was not distributed with this
// file, You can obtain one at https://mozilla.org/MPL/2.0/.

//! # Dominion
//!
//! A crate to implement DNS [Server]s and clients.
//!
//! ## Server
//!
//! ```no_run
//! use dominion::{Server, ServerService, DnsPacket};
//! use std::net::SocketAddr;
//!
//! struct Echo;
//!
//! impl ServerService for Echo {
//!     fn run<'a>(&self, _client: SocketAddr, question: DnsPacket<'a>) -> Option<DnsPacket<'a>> { Some(question) }
//! }
//!
//! Server::default()
//!         .bind("127.0.0.1:5353".parse().unwrap())
//!         .unwrap()
//!         .serve(Echo);
//! ```
//!
//! ## Client
//!

#![forbid(unsafe_code)]
#![warn(
    missing_docs,
    rust_2018_idioms,
    missing_debug_implementations,
    rustdoc::broken_intra_doc_links
)]

use std::{
    io, marker,
    net::{SocketAddr, UdpSocket},
};

pub use dominion_parser::body::name::*;
pub use dominion_parser::body::*;
pub use dominion_parser::header::*;
pub use dominion_parser::*;

/// A DNS service, it recieves a [DnsPacket] as a question and it has to return anotherone as a response.
///
/// ```rust
/// use dominion::{ServerService, DnsPacket};
/// use std::net::SocketAddr;
///
/// struct Echo;
///
/// impl ServerService for Echo {
///     fn run<'a>(&self, _client: SocketAddr, question: DnsPacket<'a>) -> Option<DnsPacket<'a>> { Some(question)}
/// }
/// ```
pub trait ServerService {
    /// Take a [DnsPacket] as an question and return the response to be sent to the client.
    fn run<'a>(&self, client: SocketAddr, question: DnsPacket<'a>) -> Option<DnsPacket<'a>>;
}

#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct Builder;
#[doc(hidden)]
#[derive(Clone, Copy, Debug)]
pub struct Runner;

/// A DNS server
#[derive(Debug)]
pub struct Server<S> {
    threads: usize,
    socket: Option<UdpSocket>,
    typestate: marker::PhantomData<S>,
}

impl<S> Server<S> {
    /// Create a new [Server]
    pub fn new() -> Server<Builder> {
        Server::<Builder>::default()
    }
}

impl Default for Server<Builder> {
    fn default() -> Self {
        Server {
            threads: 1,
            socket: None,
            typestate: marker::PhantomData,
        }
    }
}

impl Server<Builder> {
    /// Set the number of threads in the thread-pool.
    pub fn threads(mut self, n: usize) -> Self {
        self.threads = n;
        self
    }

    /// Bind to a [SocketAddr] to listen for [DnsPacket]s.
    pub fn bind(self, addr: SocketAddr) -> Result<Server<Runner>, io::Error> {
        Ok(Server {
            threads: self.threads,
            socket: Some(UdpSocket::bind(addr)?),
            typestate: marker::PhantomData::<Runner>,
        })
    }
}
impl Server<Runner> {
    /// Run the [ServerService] in the thread-pool.
    ///
    /// If an error is encountered when parsing the [DnsPacket] the error is silently droped.
    pub fn serve<T>(self, srv: T)
    where
        T: ServerService + Sync,
    {
        std::thread::scope(|s| {
            for _ in 0..self.threads {
                s.spawn(|| {
                    self.serve_sth(&srv)
                        .expect("Unexpected error when sending or recieving from the socket")
                });
            }
        })
    }

    fn serve_sth(&self, srv: &impl ServerService) -> Result<(), std::io::Error> {
        let mut buff = [0; 512];
        loop {
            let (n, src) = self
                .socket
                .as_ref()
                .expect("Runners can only be created with a active socket")
                .recv_from(&mut buff)?;
            let packet = match DnsPacket::try_from(&buff[..n]) {
                Ok(packet) => packet,
                Err(_) => continue,
            };
            if let Some(res) = srv.run(src, packet) {
                let serialized = Vec::<u8>::from(&res);
                self.socket
                    .as_ref()
                    .expect("Runners can only be created with a active socket")
                    .send_to(&serialized[..], src)?;
            };
        }
    }
}
