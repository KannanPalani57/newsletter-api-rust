use secrecy::ExposeSecret;
use newsletter::configuration::get_configuration;
use newsletter::startup::run;
use newsletter::telemetry::{get_subscriber, init_subscriber};
use sqlx::PgPool;
use std::net::TcpListener;
use newsletter::email_client::EmailClient;

#[tokio::main]
async fn main() -> Result<(), std::io::Error> {
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
