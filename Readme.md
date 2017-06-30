This is a little proxy I used to compare DNS request performance via UDP and TCP.

Description
===========

![example usage of the proxy][schema]

In client mode, the proxy takes UDP DNS requests and forwards them via TCP to a specified name server or another instance of itself in server mode. This server mode instance converts the requests back into UDP requests and forwards them to a name server. Once the server instance receives an answer, it forwards it back to the client proxy which forwards it back via UDP to the DNS client that initiated the DNS request.

The difference between using this proxy and using a DNS client in TCP mode is that the proxy uses only one TCP connection.

The proxy also has a UDP mode (option `-u`) to just forward all incoming queries via UDP.

The figure above shows how I used the proxy for my measurements, however the proxy can also be used directly with a DNS server in both, client and server mode, because all name servers should support UDP and TCP.

Usage
=====

To compile, execute `make`. The binary is also available in the root of this repository. Only tested with Linux.

For an example usage on localhost (DNS server must run and listen on port 53), see file `test.sh`.

Once the client (could be an instance of the proxy or a normal DNS client) closes the TCP connection, the proxy server instance exits, unless the option `-k` is given.

  [schema]: ./schema.png
