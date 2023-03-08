use std::env;
use argon2::{
        password_hash::{
                rand_core::OsRng,
                SaltString, PasswordHash, PasswordHasher, PasswordVerifier
    }, 
    Argon2
};

fn main() -> anyhow::Result<()> {
    
    let args: Vec<String> = env::args().collect(); 
    if args.len() < 2 {
        eprintln!("usage ./{} <password>", args[0]);
        anyhow::bail!("missing command line arguments");
    }

    let password = args[1].as_bytes();

    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();
    let password_hash = match argon2.hash_password(password, &salt) {
        Ok(v) => v.to_string(),
        Err(e) => anyhow::bail!("{e}")
    };

    let parsed_hash = match PasswordHash::new(&password_hash) {
        Ok(v) => v,
        Err(e) => anyhow::bail!("{e}")
    };



    assert!(Argon2::default().verify_password(password, &parsed_hash).is_ok());
    println!("OK: {}\nSalt: {}", password_hash, salt);

    Ok(())
}
