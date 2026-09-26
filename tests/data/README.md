# Vendored test data

`cloudflare-web-bot-auth-architecture-v1.json` is vendored verbatim from
[`cloudflare/web-bot-auth`](https://github.com/cloudflare/web-bot-auth)
(`packages/web-bot-auth/test/test_data/`), licensed Apache-2.0. It contains the
project's published architecture test vectors, including their **public test
keys** (the private halves are published in that repository and in RFC 9421;
they are not secrets).

Our tests exercise the Ed25519 vectors only; `rsa-pss-sha512` support is a
planned follow-up.
