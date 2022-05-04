# SUID Binary

suid-binary is used to model the following TTP in the SandWorm scenario:

```
Abuse Elevation Control Mechanism: Setuid and Setgid

Exaramel for Linux can execute commands with high privileges via a specific binary with setuid functionality.
```
## Quick Start

```bash
# build suid-binary
make

# upload suid-binary to target
How you get here is up to you

# once on target, switch to root, and set the suid bit
chown root:root suid-binary
chmod 4755 suid-binary

# switch to a low privilege user, and run suid-binary
./suid-binary /bin/sh
```

## Build Instructions

Use the 'make' utility as follows:

```bash
# build program
make
```

## Test Instructions

Test suid-binary with Python:

```bash
python3 test-suid-binary.py
````

## Usage Examples

```bash
# Assuming you've already uploaded suid-binary to target and set the SUID bit:
./suid-binary whoami
```

### Cleanup Instructions
Just delete suid-binary from disk:

```bash
rm suid-binary
```

### CTI Evidence

https://www.cert.ssi.gouv.fr/uploads/CERTFR-2021-CTI-005.pdf
