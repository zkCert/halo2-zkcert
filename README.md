# halo2-zkcert

Halo2 library to verify a chain of certificates. Currently supports RSA signature scheme and SHA256 hash function. In the future, we can support more certificate chaining standards i.e. [here](https://github.com/rusticata/x509-parser/blob/master/src/verify.rs)

> Note: Doesn't verify the self-signed root certificate. We need a SHA1 implementation for that.

![Screenshot 2023-09-07 at 5 48 04 PM](https://github.com/zkpdf/halo2-zkcert-experimental/assets/73331595/2e85c099-54e9-49fa-969c-15b3b99f06c7)



# Uses
- [Halo2-RSA](https://github.com/zkemail/halo2-rsa)
- [Halo2-SHA256-Unoptimized](https://github.com/zkpdf/halo2-sha256-unoptimized/)

