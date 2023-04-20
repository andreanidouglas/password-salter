use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use clap::{Parser, Subcommand};

#[derive(Subcommand, Debug)]
enum VerifyArgs {
    Verify {
        #[arg(short = 'r', long)]
        hash_password: String,
    },
}

#[derive(Parser, Debug)]
struct Args {
    #[arg(short, long)]
    password: String,

    #[command(subcommand)]
    verify: Option<VerifyArgs>,
}

fn create_hash(password: &[u8]) -> anyhow::Result<String> {
    let salt = SaltString::generate(&mut OsRng);

    let argon2 = Argon2::default();
    let password_hash = match argon2.hash_password(password, &salt) {
        Ok(v) => v.to_string(),
        Err(e) => anyhow::bail!("Could not create hash: {e}"),
    };
    Ok(password_hash)
}

fn verify(password_hash: String, password: &[u8]) -> anyhow::Result<bool> {
    let parsed_hash = match PasswordHash::new(&password_hash) {
        Ok(v) => v,
        Err(e) => anyhow::bail!("could not verify hash: {e}"),
    };

    if Argon2::default()
        .verify_password(password, &parsed_hash)
        .is_ok()
    {
        Ok(true)
    } else {
        Ok(false)
    }
}

fn main() -> anyhow::Result<()> {
    let cli = Args::parse();

    match &cli.verify {
        Some(VerifyArgs::Verify { hash_password }) => {
            if verify(String::from(hash_password), cli.password.as_bytes())? {
                println!("OK: Password and hash do match.");
            } else {
                println!("WARN: Password and hash do not match.")
            }

            Ok(())
        }
        None => {
            let hash = create_hash(cli.password.as_bytes())?;
            println!("OK: {hash}");
            Ok(())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn is_able_to_create_hash() {
        let test_password = "12345".as_bytes();
        let hashed_password = create_hash(test_password).unwrap();

        assert_eq!(verify(hashed_password, test_password).unwrap(), true);
    }

    #[test]
    fn can_verify_a_existing_hash() {
        let hash = "$argon2id$v=19$m=19456,t=2,p=1$3Ysgw68X4BsorZTBKsHVrg$2RIXjIWMe60537YHikP8VFJKK9USU2+B1HEHtKVOf2Y".to_string();
        assert!(verify(hash, "78900".as_bytes()).unwrap());
    }
}
