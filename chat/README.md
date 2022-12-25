
# Dominion Chat

DNS chat server for fun and profit

Messages can be sent in clear text or xor encrypted:

```sh
$ dig @127.0.0.1 -p 5533 hello-world.example.com
$ dig @127.0.0.1 -p 5533 xor.6b666f6f6c23706660716677.example.com
```

Giving:

![dominion-chat](https://github.com/lopukhov/dominion/raw/HEAD/chat/assets/dominion-chat-hello-world.png)

A file can also be requested, getting its encrypted contents:

![dominion-chat](https://github.com/lopukhov/dominion/raw/HEAD/chat/assets/dominion-chat-txt.png)

# Usage

```
Usage: dchat [-t <threads>] [-p <port>] [-i <ip>] [-d <domain>]

Receive DNS messages from the world

Options:
  -t, --threads     number of threads in the thread pool
  -p, --port        UDP port to listen to
  -i, --ip          ip to listen to
  -d, --domain      domain name to use as a filter
  --help            display usage information
```

# Configuration file

If a file called `configuration.toml` exists in the current directory it will be read to configure `dominion-chat`.

Example:

```toml
ip = "0.0.0.0"
port = 5353
domain = "example.com"
threads = 1

[xor]
key = 3
signal = "test"

[files]
this = "test1.txt"
is = "test2.txt"
an = "test3.txt"
example = "test4.txt"
```
