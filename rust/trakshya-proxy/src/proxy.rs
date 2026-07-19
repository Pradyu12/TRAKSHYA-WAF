use crate::config::AppState;
use crate::inspector::RequestInspector;
use axum::{body::Body, extract::Request, response::Response};
use bytes::Bytes;
use http_body_util::BodyExt;
use hyper::StatusCode;
use std::sync::Arc;

pub async fn handle_proxy_request(state: Arc<AppState>, req: Request) -> Response {
    let client_ip = RequestInspector::extract_client_ip(req.headers());
    let uri_path = req.uri().path().to_lowercase();
    let query = req.uri().query().unwrap_or("").to_string();
    let decoded_query = urlencoding::decode(&query).unwrap_or_default();
    let method = req.method().to_string();

    let (parts, body) = req.into_parts();
    let body_bytes = match BodyExt::collect(body).await {
        Ok(collected) => collected.to_bytes(),
        Err(_) => {
            return Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(Body::from("Failed to read body"))
                .unwrap()
        }
    };

    let inspector = RequestInspector::new(&state);
    if let Err(block) = inspector
        .inspect(&uri_path, &decoded_query, &method, &body_bytes, &client_ip)
        .await
    {
        return block;
    }

    let cfg = state.config.read().await;
    let upstream_url = cfg.proxy.upstream_url.clone();
    drop(cfg);

    forward_to_upstream(
        &upstream_url,
        &method,
        &uri_path,
        &query,
        parts.headers,
        body_bytes,
    )
    .await
}

async fn forward_to_upstream(
    upstream_url: &str,
    method: &str,
    path: &str,
    query: &str,
    headers: axum::http::HeaderMap,
    body: Bytes,
) -> Response {
    let upstream = format!(
        "{}{}{}",
        upstream_url.trim_end_matches('/'),
        path,
        if query.is_empty() {
            String::new()
        } else {
            format!("?{}", query)
        }
    );

    let client = reqwest::Client::new();
    let mut req_builder = match method {
        "GET" => client.get(&upstream),
        "POST" => client.post(&upstream).body(body.to_vec()),
        "PUT" => client.put(&upstream).body(body.to_vec()),
        "PATCH" => client.patch(&upstream).body(body.to_vec()),
        "DELETE" => client.delete(&upstream),
        "HEAD" => client.head(&upstream),
        _ => client.get(&upstream),
    };

    for (key, value) in headers.iter() {
        if let Ok(v) = value.to_str() {
            req_builder = req_builder.header(key.as_str(), v);
        }
    }

    match req_builder.send().await {
        Ok(resp) => {
            let status = resp.status();
            let resp_headers = resp.headers().clone();
            let resp_body = resp.bytes().await.unwrap_or_default();

            let mut response = Response::builder().status(status);
            for (key, value) in resp_headers.iter() {
                if key != "transfer-encoding" {
                    response = response.header(key.as_str(), value.to_str().unwrap_or(""));
                }
            }
            response.body(Body::from(resp_body)).unwrap_or_else(|_| {
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap()
            })
        }
        Err(e) => {
            tracing::error!("Upstream request failed: {}", e);
            Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(Body::from("Upstream unavailable"))
                .unwrap()
        }
    }
}
