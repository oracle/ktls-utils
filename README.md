# Release Notes for ktls-utils 0.6

Note well: This is experimental prototype software. It's purpose is
purely as a demonstration and proof-of-concept. USE AT YOUR OWN RISK.

In-kernel TLS consumers need a mechanism to perform TLS handshakes
on a connected socket to negotiate TLS session parameters that can
then be programmed into the kernel's TLS record protocol engine.

This package of software provides a TLS handshake user agent that
listens for kernel requests and then materializes a user space
socket endpoint on which to perform these handshakes. The resulting
negotiated session parameters are passed back to the kernel via
standard kTLS socket options.

See [COPYING](COPYING) for the full text of the license under which
this package is released.

## Dependencies

* The local kernel must be built with CONFIG_TLS enabled
* The local kernel must have experimental AF_TLSH support
* The local build environment requires GnuTLS and keyutils

## Installation

See [NEWS](NEWS) to see what has changed in the latest release,
and see [INSTALL](INSTALL) for build instructions.

## Contributing

For information on how to contribute to this project, see
[CONTRIBUTING.md](CONTRIBUTING.md). Work that remains:

### Required for client-side prototype

* Prototype requirements have all been met

### Nice-to have for client-side prototype

* support for client authentication (via certificate)
* support for using private key material stored in the local TPM
* support for session key renegotiation
* send proper SSL shutdown message when kernel consumer is finished with an endpoint
* check for the correct ALPN in the server's certificate

### Unplanned work

* support for DTLS
* support for RPC-with-TLS certificate extended key usage
* support for root device / filesystem with TLS
* support for sharing TLS sessions across sockets
* support for multiple PSK identities

### Server-side work

A server-side handshake mechanism is also needed but is not
yet part of this prototype.
