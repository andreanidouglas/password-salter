Simple password hash and salt

usage: 
```shell
$ cargo build --release
$ ./target/release/passhasher <your password>
```

dependencies:

- anyhow
- argon2
- rand_core
