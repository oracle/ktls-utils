# Release Notes for ktls-utils 1.3.0

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

### Run-time dependencies

The kernel must have net/handshake support (v6.5 or later) and be
built with the following CONFIG options enabled:

* CONFIG_TLS
* CONFIG_KEYS
* CONFIG_KEYS_REQUEST_CACHE

### Build dependencies

The build environment requires the development packages for the
following libraries to be installed:

* GnuTLS
* keyutils
* GLib-2.0
* libnl3

## Installation

See [NEWS](NEWS) to see what has changed in the latest release,
and see [INSTALL](INSTALL) for build instructions.

## Contributing

This project welcomes contributions from the community.
Before submitting a pull request,
please [review our contribution guide](./CONTRIBUTING.md).

See the GitHub Issue Tracker to review or open to-do items.

## Security

Please consult the [security guide](./SECURITY.md) for our responsible security vulnerability disclosure process

## License

Copyright (c) 2023 Oracle and/or its affiliates.

Released under the GNU GENERAL PUBLIC LICENSE version 2
