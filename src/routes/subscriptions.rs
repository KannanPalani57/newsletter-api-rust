use crate::domain::{NewSubscriber, SubscriberEmail, SubscriberName};
use actix_web::{web, HttpResponse, FromRequest, HttpRequest, HttpMessage};
use chrono::Utc;
use sqlx::PgPool;
use std::convert::{TryFrom, TryInto};
use uuid::Uuid;
use std::future::{ready, Ready};

use actix_web::{
    dev::{forward_ready, Service, ServiceRequest, ServiceResponse, Transform},
    Error,
};
use futures_util::future::LocalBoxFuture;

use core::fmt;
use actix_web::error::ErrorUnauthorized;
use actix_web::{http, dev::Payload, Error as ActixWebError};
use jsonwebtoken::{decode, DecodingKey, Validation};


#[derive(serde::Deserialize)]
pub struct FormData {
    email: String,
    name: String,
}
impl TryFrom<FormData> for NewSubscriber {
    type Error = String;

    fn try_from(value: FormData) -> Result<Self, Self::Error> {
        let name = SubscriberName::parse(value.name)?;
        let email = SubscriberEmail::parse(value.email)?;
        Ok(Self { email, name })
    }
}

#[tracing::instrument(
    name = "Adding a new subscriber", 
    skip(form, pool), 
    fields(
        subscriber_email =  %form.email,
        subscriber_name = %form.name
    )
)]
pub async fn subscribe(form: web::Form<FormData>, pool: web::Data<PgPool>) -> HttpResponse {
    let new_subscriber = match form.0.try_into() {
        Ok(form) => form,
        Err(_) => return HttpResponse::BadRequest().finish(),
    };
    match insert_subscriber(&pool, &new_subscriber).await {
        Ok(_) => HttpResponse::Ok().finish(),
        Err(_) => HttpResponse::InternalServerError().finish(),
    }
}

#[tracing::instrument(
    name = "Saving new subscriber details in the database",
    skip(new_subscriber, pool)
)]
pub async fn insert_subscriber(
    pool: &PgPool,
    new_subscriber: &NewSubscriber,
) -> Result<(), sqlx::Error> {
    sqlx::query!(
        r#"
    INSERT INTO subscriptions (id, email, name, subscribed_at)
    VALUES ($1, $2, $3, $4)
            "#,
        Uuid::new_v4(),
        new_subscriber.email.as_ref(),
        new_subscriber.name.as_ref(),
        Utc::now()
    )
    .execute(pool)
    .await
    .map_err(|e| {
        tracing::error!("Failed to execute query: {:?}", e);
        e
    })?;
    Ok(())
}


#[derive(Debug, serde::Serialize)]
struct ErrorResponse {
    status: String,
    message: String,
}

impl fmt::Display for ErrorResponse {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(f, "{}", serde_json::to_string(&self).unwrap())
    }
}


pub struct JwtMiddleware {
    pub user_id: Uuid,
}


#[derive(Debug, serde::Serialize, serde::Deserialize)]
pub struct TokenClaims {
    pub sub: String,
    pub iat: usize,
    pub exp: usize,
}

impl FromRequest for JwtMiddleware {
    type Error = ActixWebError;
    type Future = Ready<Result<Self, Self::Error>>;
    fn from_request(req: &HttpRequest, _: &mut Payload) -> Self::Future {

        println!("hiii");

        let token = req
        .cookie("token")
        .map(|c| c.value().to_string())
        .or_else(|| {
            req.headers()
                .get(http::header::AUTHORIZATION)
                .map(|h| h.to_str().unwrap().split_at(7).1.to_string())
        });

    if token.is_none() {
        let json_error = ErrorResponse {
            status: "fail".to_string(),
            message: "You are not logged in, please provide token".to_string(),
        };
        return ready(Err(ErrorUnauthorized(json_error)));
    }

    let claims = match decode::<TokenClaims>(
        &token.unwrap(),
        &DecodingKey::from_secret(b"secret"),
        &Validation::default(),
    ) {
        Ok(c) => c.claims,
        Err(_) => {
            let json_error = ErrorResponse {
                status: "fail".to_string(),
                message: "Invalid token".to_string(),
            };
            return ready(Err(ErrorUnauthorized(json_error)));
        }
    };

    let user_id = uuid::Uuid::parse_str(claims.sub.as_str()).unwrap();
    req.extensions_mut()
        .insert::<uuid::Uuid>(user_id.to_owned());

    ready(Ok(JwtMiddleware { user_id }))
    }
}


pub async fn auth_req(jwt:JwtMiddleware, pool: web::Data<PgPool>) -> HttpResponse {

    HttpResponse::Ok().finish()

}
