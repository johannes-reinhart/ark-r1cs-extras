# SNARK R1CS Crypto Gadgets

This repository includes the following R1CS gadgets:
* [`Curve`](src/curve): Efficient fixed-base elliptic curve scalar multiplication in montgomery coordinates with 3-bit lookup tables  
* [`Poseidon`](src/crh/poseidon.rs): Poseidon hash with precomputed parameters for scalar fields of various pairing-friendly elliptic curves
* [`EdDSA`](src/signature/eddsa): EdDSA signature verification
   - with Bowe-Hopwood (ZCash-Style Pedersen) hash
   - with Poseidon hash
* [`Schnorr`](src/signature/schnorr): Schnorr signature verification
   - with Bowe-Hopwood (ZCash-Style Pedersen) hash
   - with Poseidon hash
