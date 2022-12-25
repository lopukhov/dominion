
# Dominion Chat

DNS chat server for fun and profit

Running the following command:

```
sh-5.1$ dig @127.0.0.1 -p 5353 hello-world.example.com +short
127.0.0.1
```

Gives:

![dominion-chat](https://github.com/lopukhov/dominion/raw/HEAD/chat/assets/dominion-chat-hello-world.png)

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
