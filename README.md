# SNARK R1CS Gadgets and Tools

The arkworks ecosystem consists of Rust libraries for designing and working with __zero knowledge succinct non-interactive arguments (zkSNARKs)__. This repository contains R1CS gadgets as well as tools for analysing R1CS circuits.  

This library is released under the MIT License and the Apache v2 License (see [License](#license)).

**WARNING:** This is an academic proof-of-concept prototype, and in particular has not received careful code review. This implementation is NOT ready for production use.

## Directory structure

This repository contains two Rust crates:

* [`ark-crypto-gadgets`](crypto-gadgets): Provides R1CS gadgets for cryptographic primitives
* [`ark-tools`](tools): Provides tools for analyzing R1CS circuits

## Overview

This repository provides extensions to the arkworks ecosystem. The crypto-gadgets crate includes ready to use R1CS circuits for the Poseidon sponge, EdDSA and Schnorr signature verification and efficient elliptic curve scalar multiplication. The tools crate provides tooling for analyzing circuits.

## License

The crates in this repo are licensed under either of the following licenses, at your discretion.

 * Apache License Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

Unless you explicitly state otherwise, any contribution submitted for inclusion in this library by you shall be dual licensed as above (as defined in the Apache v2 License), without any additional terms or conditions.


