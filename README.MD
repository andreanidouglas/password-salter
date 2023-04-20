# Simple password hash and salt.

## Usage

To create a password hash:
```shell
$ ./passhasher --password '<YOUR-PASSWORD>'
```

To verify a password hash:
```shell
$ ./passhasher --password '<YOUR-PASSWORD>' verify --hash_password '<PASSWORD-HASH>'
```

## Build

[![Build Status](https://ci.delta.labs.andreanidr.com/buildStatus/icon?job=Password-Salter/main)](https://ci.delta.labs.andreanidr.com/job/Password-Salter/)

```shell
$ cargo build [--release]
```

dependencies:

- anyhow
- argon2
- clap
- rand_core
