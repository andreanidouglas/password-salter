#Simple password hash and salt.

To create a password hash:
```shell
$ cargo build --release
$ ./target/release/passhasher --password <YOUR-PASSWORD>
```

To verify a password hash:
```shell
$ cargo build --release
$ ./target/release/passhasher --password <YOUR-PASSWORD> verify --hash_password <PASSWORD-HASH>
```

dependencies:

- anyhow
- argon2
- clap
- rand_core
