# halo2-zkcert

Halo2 library to verify a chain of certificates which is used in TLS initial handshake, document signing and VPNs. Currently supports RSA signature scheme and SHA256 hash function. In the future, we can support more certificate chaining standards such as ECDSA, SHA3 etc i.e. [here](https://github.com/rusticata/x509-parser/blob/master/src/verify.rs)

> Note: Doesn't verify the self-signed root certificate which uses SHA1. This is fine because root certificates are assumed to be trusted.

![Screenshot 2023-09-07 at 5 48 04 PM](https://github.com/zkpdf/halo2-zkcert-experimental/assets/73331595/2e85c099-54e9-49fa-969c-15b3b99f06c7)

## Installation
```
git clone https://github.com/zkpdf/halo2-zkcert/
cd halo2-zkcert
cargo build --release
```

## Example Usage
```
// Import your own chain of x509 certificates and save them as PEM files in `certs` folder. Where 1 is root certificate and 3 is leaf certificate
// OR
cargo run --release download-tls-certs --domain axiom.xyz --certs-path ./certs/cert
// Generate RSA proving keys
cargo run --release -- gen-rsa-keys --k 17 --pk-path ./build/rsa.pk --verify-cert-path ./certs/cert_3.pem --issuer-cert-path ./certs/cert_2.pem
// Generate SHA256 proving keys
// TODO: fast ZKEVM SHA256 is not fully working so we use unoptimized for now
cargo run --release -- gen-unoptimized-sha256-keys --k 19 --pk-path ./build/unoptimized_sha256.pk --verify-cert-path ./certs/cert_3.pem
// Generate proving keys for X509AggregationCircuit
cargo run --release -- gen-x509-agg-keys --agg_k 22
// Prove RSA
cargo run --release -- prove-rsa --pk-path ./build/rsa.pk --verify-cert-path ./certs/cert_3.pem --issuer-cert-path ./certs/cert_2.pem
cargo run --release -- prove-rsa --pk-path ./build/rsa.pk --verify-cert-path ./certs/cert_2.pem --issuer-cert-path ./certs/cert_1.pem
// Prove SHA256
cargo run --release prove-unoptimized-sha256 --pk-path ./build/unoptimized_sha256.pk --verify-cert-path ./certs/cert_3.pem --proof-path ./build/unoptimized_sha256_1.proof
cargo run --release prove-unoptimized-sha256 --pk-path ./build/unoptimized_sha256.pk --verify-cert-path ./certs/cert_2.pem --proof-path ./build/unoptimized_sha256_2.proof
// Prove aggregation and verify in smart contract
cargo run --release -- gen-x509-agg-evm-proof
```

## Test
```
cargo test
```

## Benchmarks
| Circuit                          | `k` | Num Advice | Num Lookup Advice | Num Fixed | Proof Time (M1 16GB)  | Proof Time (EC2 c6a.48xlarge) |
| ---------------------------------| --- | ---------- | ----------------- | --------- | --------------------- | ----------------------------- |
| SHA256 (unoptimized - 1280 bytes)| 16  | 81         | 1                 | 1         | 15.870s               | 15.947s                       |
| SHA256 (unoptimized - 1280 bytes)| 17  | 41         | 1                 | 1         | 16.432s               | 12.617s                       |
| SHA256 (unoptimized - 1280 bytes)| 18  | 21         | 1                 | 1         | 17.857s               | 11.771s                       |
| SHA256 (unoptimized - 1280 bytes)| 19  | 11         | 1                 | 1         | 20.724s               | 13.406s                       |
| RSA                              | 15  | 12         | 1                 | 1         | 1.783s                | 1.245s                        |
| RSA                              | 16  | 6          | 1                 | 1         | 2.224s                | 1.509s                        |
| RSA                              | 17  | 3          | 1                 | 1         | 3.144s                | 1.813s                        |
| X509Aggregation (SHA256 k=19, RSA k=17) | 22  | 5          | 1                 | 1  | N/A | 17.188s (reading pk) + 44.131s (proof gen)     |

## Dependencies
- [Halo2-RSA](https://github.com/zkpdf/halo2-rsa) (Fork of zkemail halo2-rsa that is compatible with halo2-lib v4)
- [Halo2-SHA256-Unoptimized](https://github.com/zkpdf/halo2-sha256-unoptimized/)
- [ZKEVM SHA256](https://github.com/axiom-crypto/halo2-lib/tree/feat/zkevm-sha256/hashes/zkevm/src/sha256)

## Issues
Current issues and todos with the library. We welcome any contributions!
1. Script to download TLS certs doesn't match manually inspecting the certs and downloading
2. Doesn't support other certificate chaining standards, such as ECDSA and SHA3 yet
3. Doesn't support CRL (certificate revocation lists yet)
4. For RSA and SHA256 circuits, Mock prover is satisfied, but cannot verify a real proof (we can create proof, but fails in vk). Is it something to do with my snark-verifier version?
