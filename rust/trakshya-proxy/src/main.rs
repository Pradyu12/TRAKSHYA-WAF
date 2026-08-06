mod api;
mod config;
mod db;
mod gateway;
mod inspector;
mod middleware;
mod proxy;

use axum::{
    extract::{DefaultBodyLimit, Request},
    http::{header, Method},
    middleware::{self, Next},
    response::Response,
    routing::{any, get},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::cors::{Any, CorsLayer};
use tracing_subscriber::EnvFilter;

/// Security headers middleware — adds hardening headers to every response.
async fn security_headers(mut req: Request, next: Next) -> Response {
    let mut response = next.run(req).await;
    let headers = response.headers_mut();
    headers.insert("x-content-type-options", "nosniff".parse().unwrap());
    headers.insert("x-frame-options", "DENY".parse().unwrap());
    headers.insert("x-xss-protection", "1; mode=block".parse().unwrap());
    headers.insert("referrer-policy", "strict-origin-when-cross-origin".parse().unwrap());
    headers.insert("permissions-policy", "camera=(), microphone=(), geolocation=()".parse().unwrap());
    headers.insert("cache-control", "no-store, no-cache, must-revalidate".parse().unwrap());
    response
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env().add_directive(tracing::Level::INFO.into()))
        .init();

    let cfg = config::Config::load()?;
    let state = Arc::new(config::AppState::new(&cfg)?);

    let proxy_state = state.clone();
    let make_handler = {
        let state = proxy_state.clone();
        move || {
            let state = state.clone();
            move |req: Request| {
                let state = state.clone();
                async move { proxy::handle_proxy_request(state, req).await }
            }
        }
    };

    // Configure CORS for the management API
    let cors = CorsLayer::new()
        .allow_origin(Any)
        .allow_methods([Method::GET, Method::POST, Method::PUT, Method::DELETE, Method::OPTIONS])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION, header::X_API_KEY, header::X_FORWARDED_FOR])
        .max_age(300);

    let app = Router::new()
        .nest("/api", api::mgmt_router(state.clone()))
        .route("/health", get(health_check))
        .route("/", any(make_handler()))
        .route("/*path", any(make_handler()))
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024))
        .layer(cors)
        .layer(middleware::from_fn(security_headers));

    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.proxy.port));
    tracing::info!("TRAKSHYA-WAF proxy listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;

    // Graceful shutdown: handle Ctrl+C and SIGTERM
    let shutdown = tokio::signal::unix::signal(tokio::signal::unix::SignalKind::terminate())
        .ok()
        .into_iter()
        .chain(tokio::signal::ctrl_c().into_iter())
        .into_future();

    tracing::info!("TRAKSHYA-WAF ready. Press Ctrl+C or send SIGTERM to stop.");

    axum::serve(listener, app)
        .with_graceful_shutdown(async {
            shutdown.await;
            tracing::info!("Shutting down TRAKSHYA-WAF...");
        })
        .await?;

    tracing::info!("TRAKSHYA-WAF stopped.");
    Ok(())
}

async fn health_check() -> &'static str {
    "OK"
}
