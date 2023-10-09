# File Hashes

This directory contains files hashes that can be used to verify integrity of the
Resources used in this adversary emulation plan.

It is recommended that users hash executables and scripts prior to execution to confirm
that illicit changes have not been made.

- [SHA256](./hash_SHA256.txt)
- [SHA512](./hash_SHA512.txt)

To refresh the hashes, run these commands:

```bash
$ find Resources -type f | sort | xargs sha256sum > Hashes/hash_SHA256.txt
$ find Resources -type f | sort | xargs sha512sum > Hashes/hash_SHA512.txt
```
