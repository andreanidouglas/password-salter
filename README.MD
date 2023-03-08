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
```shell
$ cargo build [--release]
```

dependencies:

- anyhow
- argon2
- clap
- rand_core
