Kyanite Core
=============

Setup
---------------------
[Kyanite Core](https://kyancoin.net/) is the original Kyanite client and it builds the backbone of the network. However, it downloads and stores the entire history of Kyanite transactions; depending on the speed of your computer and network connection, the synchronization process can take anywhere from a few hours to a day or more. Thankfully you only have to do this once.

Running
---------------------
The following are some helpful notes on how to run Kyanite Core on your native platform.

### Unix

Unpack the files into a directory and run:

- `bin/kyanite-qt` (GUI) or
- `bin/kyanited` (headless)

### Windows

Unpack the files into a directory, and then run Kyanite-qt.exe.

### macOS

Drag Kyanite-Qt to your applications folder, and then run Kyanite-Qt.

### Need Help?

* See the documentation at the [Kyanite Wiki](https://github.com/decenomy/KYAN/)
for help and more information.
* Join our Discord server [Discord Server](https://discord.gg/R2Racbr)

Building
---------------------
The following are developer notes on how to build Kyanite Core on your native platform. They are not complete guides, but include notes on the necessary libraries, compile flags, etc.

- [Dependencies](dependencies.md)
- [macOS Build Notes](build-osx.md)
- [Unix Build Notes](build-unix.md)
- [Windows Build Notes](build-windows.md)
- [Gitian Building Guide](gitian-building.md)

Development
---------------------
The Kyanite repo's [root README](/README.md) contains relevant information on the development process and automated testing.

- [Developer Notes](developer-notes.md)
- [Multiwallet Qt Development](multiwallet-qt.md)
- [Release Notes](release-notes.md)
- [Release Process](release-process.md)
- [Source Code Documentation (External Link)](https://github.com/decenomy/KYAN/)
- [Translation Process](translation_process.md)
- [Unit Tests](unit-tests.md)
- [Unauthenticated REST Interface](REST-interface.md)
- [Dnsseed Policy](dnsseed-policy.md)

### Resources
* Discuss on the [Kyanite Homepage](https://kyancoin.net/).
* Join the [Kyanite Discord](https://discord.gg/R2Racbr).

### Miscellaneous
- [Assets Attribution](assets-attribution.md)
- [Files](files.md)
- [Tor Support](tor.md)
- [Init Scripts (systemd/upstart/openrc)](init.md)

License
---------------------
Distributed under the [MIT software license](/COPYING).
This product includes software developed by the OpenSSL Project for use in the [OpenSSL Toolkit](https://www.openssl.org/). This product includes
cryptographic software written by Eric Young ([eay@cryptsoft.com](mailto:eay@cryptsoft.com)), and UPnP software written by Thomas Bernard.
