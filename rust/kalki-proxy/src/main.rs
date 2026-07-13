mod proxy;
mod inspector;
mod middleware;
mod config;
mod api;

use axum::{
    extract::{DefaultBodyLimit, Request},
    response::Response,
    routing::{any, get},
    Router,
};
use std::net::SocketAddr;
use std::sync::Arc;
use tracing_subscriber::EnvFilter;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt()
        .with_env_filter(EnvFilter::from_default_env()
            .add_directive(tracing::Level::INFO.into()))
        .init();

    let cfg = config::Config::load()?;
    let state = Arc::new(config::AppState::new(&cfg).await?);

    let proxy_state = state.clone();
    let proxy_handler = move |req: Request| {
        let state = proxy_state.clone();
        async move { proxy::handle_proxy_request(state, req).await }
    };

    let app = Router::new()
        .route("/*path", any(proxy_handler))
        .nest("/api", api::mgmt_router(state.clone()))
        .route("/health", get(health_check))
        .layer(DefaultBodyLimit::max(10 * 1024 * 1024));

    let addr = SocketAddr::from(([0, 0, 0, 0], cfg.proxy_port));
    tracing::info!("KALKI-WAF proxy listening on {}", addr);

    let listener = tokio::net::TcpListener::bind(addr).await?;
    axum::serve(listener, app).await?;

    Ok(())
}

async fn health_check() -> &'static str {
    "OK"
}
