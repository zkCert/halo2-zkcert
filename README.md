# halo2-zkcert

Halo2 library to verify a chain of certificates. Currently supports RSA signature scheme and SHA256 hash function. In the future, we can support more certificate chaining standards such as ECDSA, SHA3 etc i.e. [here](https://github.com/rusticata/x509-parser/blob/master/src/verify.rs)

> Note: Doesn't verify the self-signed root certificate which uses SHA1. This is fine because root certificates are assumed to be trusted.

![Screenshot 2023-09-07 at 5 48 04 PM](https://github.com/zkpdf/halo2-zkcert-experimental/assets/73331595/2e85c099-54e9-49fa-969c-15b3b99f06c7)

## Installation
```
git clone https://github.com/zkpdf/halo2-zkcert/
cd halo2-zkcert
cargo build --release
```

## Usage
Copy certificate files into `certs` folder. See `src/bin/cli.rs` file for commands
```
cargo run --release -- gen-params --k 20
cargo run --release -- gen-unoptimized-sha256-keys --k 17 --pk-path ./build/unoptimized_sha256_2.pk --verify-cert-path ./certs/cert_2.pem
cargo run --release -- gen-rsa-keys --k 17 --pk-path ./build/rsa_2.pk --verify-cert-path ./certs/cert_2.pem --issuer-cert-path ./certs/cert_1.pem
cargo run --release -- gen-x509-agg-keys --agg_k 20
cargo run --release -- prove-unoptimized-sha256 --k 17
cargo run --release -- prove-rsa --k 17
```

## Test
```
cargo test
```


## Dependencies
- [Halo2-RSA](https://github.com/zkpdf/halo2-rsa) (Fork of zkemail halo2-rsa that is compatible with halo2-lib v4)
- [Halo2-SHA256-Unoptimized](https://github.com/zkpdf/halo2-sha256-unoptimized/)
- [ZKEVM SHA256](https://github.com/axiom-crypto/halo2-lib/tree/feat/zkevm-sha256/hashes/zkevm/src/sha256)

## Issues
Current issues with the library. We welcome any contributions!
1. Currently, there is an issue with aggregating vanilla ZKEVM SHA256 due to public instances not being exposed properly. See `sha256-bit-circuit.rs`. Therefore, we have to use an unoptimized sha256 library that is written entirely in halo2-lib v4
2. Missing script to extract chain of certificates from raw document and separate out into different PEM files in certs folder
3. Doesn't support other certificate chaining standards, such as ECDSA and SHA3 yet