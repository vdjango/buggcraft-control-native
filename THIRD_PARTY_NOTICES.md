# Third-party components

The service links mature libraries; their respective licenses and redistribution notices remain applicable. This project has no public-source license declaration yet; publication is a separate decision.

| Library | Use | Upstream license/source |
| --- | --- | --- |
| Boost.Asio / Beast | Async HTTPS/WSS and bounded node probe | [Boost Software License 1.0](https://www.boost.org/LICENSE_1_0.txt) |
| OpenSSL 3 | TLS, Ed25519, P-256, SHA-256, random generation | [Apache License 2.0](https://github.com/openssl/openssl/blob/master/LICENSE.txt) |
| PostgreSQL libpq | Parameterized database operations and transactions | [PostgreSQL License](https://www.postgresql.org/about/licence/) |
| simdjson | JSON validation/parsing with runtime ISA dispatch | [Apache License 2.0 / MIT](https://github.com/simdjson/simdjson/blob/master/LICENSE) |
| nlohmann/json | Owned domain JSON representation and serialization | [MIT](https://github.com/nlohmann/json/blob/develop/LICENSE.MIT) |
| libcurl | Verified TLS SMTP delivery | [curl license](https://curl.se/docs/copyright.html) |

Account frontend assets are built from the adjacent minecraft-tunnel-native project under its existing AGPL-3.0-or-later terms. They remain a separate frontend; keep their license and corresponding source with distribution, along with Vue and build-dependency notices. The control backend does not copy its Python implementation.

Development-only Python packages and GitHub Actions do not become service runtime dependencies. Existing node public identity/protocol fields were inspected for interoperability; their Python/C++ implementation was not copied. Legacy certificate validation here uses OpenSSL EVP and independent protocol decoding. Source/release bundles must include the notices of the actual linked versions; the Docker base and Linux packages also carry their distribution notices.
