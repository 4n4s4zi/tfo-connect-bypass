# Bypassing connect()-based syscall rules using TCP Fast Open (CVE-2026-63828 PoC)

TCP Fast Open (TFO) is a method of initializing a TCP connection where the client can send data in the initial SYN packet sent to the server. This is good for speed because the back and forth of the initial TCP handshake can be skipped. There's more to the implementation details if you care about using it in a production-level setting, but it's useful for evading some syscall-based rule engines because it's one way of opening TCP connections without using the `connect` syscall explicitly.

From a syscall perspective, a basic TCP connection generally looks like:
```
socket() -> connect() -> write()/read()
```

A TFO connection, however, is initialized using a `sendto` syscall with the `MSG_FASTOPEN` flag:
```
socket() -> sendto(...,MSG_FASTOPEN,...) -> write()/read()
```

I kind of explored this as a side quest for something else I was working on but in doing more research on TFO, CVE-2026-63828 came up as a (recent) known bypass specific to networking-confined processes in AppArmor. It applies to more than just AppArmor though so I thought I'd post a basic poc here.

Say you wanted to query a Kubernetes API server from inside a container as part of post-ex recon but there are eBPF-, AppArmor-, or some other syscall-based monitoring/blocking rules in place.
If you don't want to use a more heavy networking implementation/library in userland and other syscall evasion primitives like `io_uring` aren't available, TFO might be useful. Again, this is just a simple PoC and not a robust TFO stack.

Portable build:
```
CGO_ENABLED=0 GOOS=linux GOARCH=amd64 go build test.go
```

References:
- https://nvd.nist.gov/vuln/detail/cve-2026-63828
- https://www.sentinelone.com/vulnerability-database/cve-2026-63828
