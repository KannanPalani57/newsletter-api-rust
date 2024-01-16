use newsletter::configuration::get_configuration;
use newsletter::startup::run;
use newsletter::telemetry::{get_subscriber, init_subscriber};
use sqlx::PgPool;
use std::net::TcpListener;
use newsletter::email_client::EmailClient;

use argon2::password_hash::SaltString;
use argon2::{Algorithm, Argon2, Params, PasswordHash, PasswordHasher, PasswordVerifier, Version};
use secrecy::{ExposeSecret, Secret};
use newsletter::telemetry::spawn_blocking_with_tracing;
use anyhow::Context;

#[derive(thiserror::Error, Debug)]
pub enum AuthError {
    #[error("Invalid credentials.")]
    InvalidCredentials(#[source] anyhow::Error),
    #[error(transparent)]
    UnexpectedError(#[from] anyhow::Error),
}


fn compute_password_hash(password: Secret<String>) -> Result<Secret<String>, anyhow::Error> {
// fn compute_password_hash(password: Secret<String>) -> Result<String, anyhow::Error> {
    let salt = SaltString::generate(&mut rand::thread_rng());
    let password_hash = Argon2::new(
        Algorithm::Argon2id,
        Version::V0x13,
        Params::new(15000, 2, 1, None).unwrap(),
    )
    .hash_password(password.expose_secret().as_bytes(), &salt)?
    .to_string();
    Ok(Secret::new(password_hash))
    // Ok(password_hash)
}

fn verify_password_hash(
    expected_password_hash: Secret<String>,
    password_candidate: Secret<String>,
) -> Result<(), AuthError >  {
    let expected_password_hash = PasswordHash::new(expected_password_hash.expose_secret())
        .context("Failed to parse hash in PHC string format.")?;

    Argon2::default()
        .verify_password(
            password_candidate.expose_secret().as_bytes(),
            &expected_password_hash,
        )
        .context("Invalid password.")
        .map_err(AuthError::InvalidCredentials)
}


pub async fn   hash_string() -> Result<Secret<String>, anyhow::Error>  {
    println!("Hash String is running!");

    let name: Secret<String> = String::from("kannn").into();

    let password_hash = spawn_blocking_with_tracing(move || compute_password_hash(name))
    .await?
    .context("Failed to hash password")?;
 

    // println!(" password hash {:?}", password_hash);  
    Ok(password_hash)

}


#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
    
    let hash : Secret<String> = hash_string().await.unwrap();
    let name: Secret<String> = String::from("kannn").into();


    let verify = spawn_blocking_with_tracing(move || {
        verify_password_hash(hash, name)
    })
    .await;
    // .context("Failed to spawn blocking task.")??;
    println!("{:?} show hash",verify.unwrap());

    let subscriber = get_subscriber("newsletter".into(), "info".into(),  std::io::stdout);
    init_subscriber(subscriber);

    let configuration = get_configuration().expect("Failed to read configuration.");

    let connection_pool = PgPool::connect(&configuration.database.connection_string().expose_secret())
        .await
        .expect("Failed to connect to Postgres.");

    let sender_email = configuration.email_client.sender()
                .expect("Invalid sender email address. ");
    
    let email_client = EmailClient::new(
        configuration.email_client.base_url, 
        sender_email
    );

    let address = format!("127.0.0.1:{}", configuration.application_port);

    let listener = TcpListener::bind(address).expect("Failed to bind random port");
    run(listener, connection_pool, email_client)?.await
}
