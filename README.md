[![Build Status](https://img.shields.io/travis/mimblewimble/grin/master.svg)](https://travis-ci.org/mimblewimble/grin)
[![Coverage Status](https://img.shields.io/codecov/c/github/mimblewimble/grin/master.svg)](https://codecov.io/gh/mimblewimble/grin)
[![Chat](https://img.shields.io/gitter/room/grin_community/Lobby.svg)](https://gitter.im/grin_community/Lobby)
[![Support](https://img.shields.io/badge/support-on%20gitter-brightgreen.svg)](https://gitter.im/grin_community/support)
[![Documentation Wiki](https://img.shields.io/badge/doc-wiki-blue.svg)](https://github.com/mimblewimble/docs/wiki)
[![Release Version](https://img.shields.io/github/release/mimblewimble/grin.svg)](https://github.com/mimblewimble/grin/releases)
[![License](https://img.shields.io/github/license/mimblewimble/grin.svg)](https://github.com/mimblewimble/grin/blob/master/LICENSE)

# Vcash

VCash is the combined outcome of Bitcoin characteristics integrated with Mimblewimble technology. It inherits Bitcoin’s distribution mechanism and uses Grin's Mimblewimble implementation.

Bitcoin has proven some facts in the last ten years. For example, the best way to protect assets is consuming energy through POW, a fixed quantity of coins give rise to good performance, ASIC devices do not violate the goal of decentralisation, and decentralised systems are reliable.

Currently, Bitcoin's privacy protocol is still relatively poor whereby the flow of most transactions under the UTXO model are analysed, and transaction amounts are made public. This means there are no privacy and anonymity in Bitcoin, which in turn hinders liquidity of the coins and limits people's freedom to use the coins.

Grin's privacy protocol is second to none. It is extremely reliable and simple because it only utilises a number of basic mathematical laws. It is such a pity that the only blemish in Grin is that its coin parameter settings adopted the linear coin delivery model.

VCash combines advantages of the two coins. In terms of Bitcoin, it inherits its economic parameter as well as its immense hash power. In terms of Grin, it derives its powerful technology in privacy protocols.

VCash adopts Merged Mining method to mine coins alongside Bitcoin, that is, VCash blocks can be computed whilst computing Bitcoin blocks. In general, POW chains need to take into consideration that there is a 51% risk of attack on the network. Since Bitcoin has the largest number of miners in the world whereby hash power is broadly distributed, VCash can easily obtain most of Bitcoin’s hash power with the support of the Bitcoin mining pool. This means VCash possesses the same level of security as Bitcoin hence launching a 51% attack on it would be equally difficult.

The goal of VCash is to be the most private and secure chain for storing values.

## Getting Started

To learn more about the technology, read our [introduction](doc/intro.md).

To build and try out Vcash, see the [build docs](doc/build.md).

## Credits

Tom Elvis Jedusor for the first formulation of MimbleWimble.

Andrew Poelstra for his related work and improvements.

John Tromp for the Cuckoo Cycle proof of work.

J.K. Rowling for making it despite extraordinary adversity.

## License

Apache License v2.0.
