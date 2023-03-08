use argon2::{
    password_hash::{rand_core::OsRng, PasswordHasher, SaltString},
    Argon2, PasswordHash, PasswordVerifier,
};
use clap::{Parser, Subcommand};

#[derive(Subcommand, Debug)]
enum VerifyArgs {
    Verify {
        #[arg(short='r', long)]
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
    Ok(password_hash.to_string())
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
            if verify(String::from(hash_password), cli.password.as_bytes())?{
                println!("OK: Password and hash do match.");
            } else {
                println!("WARN: Password and hash do not match.")
            }
            
            Ok(())
        },
        None => {
            let hash = create_hash(cli.password.as_bytes())?;
            println!("OK: {hash}");
            Ok(())
        }
    }


}
