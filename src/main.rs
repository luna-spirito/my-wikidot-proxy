use axum::{
    body::Body,
    extract::{Request, State},
    http::{header, HeaderValue, StatusCode},
    response::{IntoResponse, Response},
    routing::any,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use regex::Regex;
use reqwest::{Client, Proxy};
use serde::Deserialize;
use std::collections::HashMap;
use std::fs;
use std::net::SocketAddr;
use std::sync::Arc;
use tower_http::{compression::CompressionLayer, validate_request::ValidateRequestHeaderLayer};
use tracing::{debug, error, info, warn};

#[derive(Deserialize, Clone)]
struct Config {
    domain: String,
    listen_addr: String,
    upstream_proxy: String,
    ssl_cert: String,
    ssl_key: String,
    proxy_to_raw: HashMap<String, String>,
}

#[derive(Clone)]
struct AppState {
    client: Client,
    proxy_to: HashMap<String, String>,
    substitutions: Vec<Substitution>,
    domain: String,
}

#[derive(Clone)]
struct Substitution {
    from: Regex,
    to: String,
}

const WIKIDOT_SPACE_NAME: &str = "wikidot";

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    tracing_subscriber::fmt::init();

    info!("Starting Wikidot Proxy application");

    // Fix for "Could not automatically determine the process-level CryptoProvider"
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Load config from file
    let config_path = std::env::args()
        .nth(1)
        .unwrap_or_else(|| "config.toml".to_string());

    info!("Loading configuration from: {}", config_path);
    let config_str = fs::read_to_string(&config_path).map_err(|e| {
        error!("Failed to read config file {}: {}", config_path, e);
        e
    })?;

    let config: Config = toml::from_str(&config_str).map_err(|e| {
        error!("Failed to parse TOML config: {}", e);
        e
    })?;

    // Load secrets from ENV
    let auth_user = std::env::var("PROXY_USER").unwrap_or_else(|_| {
        warn!("PROXY_USER not set in environment, basic auth might fail or use defaults if handled elsewhere");
        String::new()
    });
    let auth_pass = std::env::var("PROXY_PASS").unwrap_or_else(|_| {
        warn!("PROXY_PASS not set in environment");
        String::new()
    });

    if auth_user.is_empty() || auth_pass.is_empty() {
        error!("Both PROXY_USER and PROXY_PASS must be provided for basic authentication");
        anyhow::bail!("Missing authentication credentials");
    }

    // 1. Setup mappings
    let mut proxy_to = HashMap::new();
    proxy_to.insert(
        WIKIDOT_SPACE_NAME.to_string(),
        "www.wikidot.com".to_string(),
    );

    for (proxy, target) in &config.proxy_to_raw {
        let host = format!("{}.wikidot.com", target);
        let files_host = format!("{}.wdfiles.com", target);
        proxy_to.insert(proxy.clone(), host);
        proxy_to.insert(format!("files.{}", proxy), files_host);
    }
    info!("Mapped {} subdomains", proxy_to.len());

    // 2. Setup substitutions
    let mut substitutions = Vec::new();
    let cloudfront_re = Regex::new(r"http:(//|\\/\\/)d3g0gp89917ko0\.cloudfront\.net")?;
    substitutions.push(Substitution {
        from: cloudfront_re,
        to: "https:${1}d3g0gp89917ko0.cloudfront.net".to_string(),
    });

    for (proxy, target) in &proxy_to {
        let from_str = format!("http://{}", target);
        let from_re = Regex::new(&regex::escape(&from_str))?;
        substitutions.push(Substitution {
            from: from_re,
            to: format!("https://{}{}", proxy, config.domain),
        });

        let target_escaped = regex::escape(target);
        let complex_pattern = format!(r#"(["']|:\\/\\/){}"#, target_escaped);
        let complex_re = Regex::new(&complex_pattern)?;
        substitutions.push(Substitution {
            from: complex_re,
            to: format!("${{1}}{}{}", proxy, config.domain),
        });
    }
    info!("Initialized {} substitution rules", substitutions.len());

    // 3. Configure Reqwest with Upstream Proxy
    info!("Configuring upstream proxy: {}", config.upstream_proxy);
    let client = Client::builder()
        .proxy(Proxy::all(&config.upstream_proxy).map_err(|e| {
            error!(
                "Invalid upstream proxy URL '{}': {}",
                config.upstream_proxy, e
            );
            e
        })?)
        .danger_accept_invalid_certs(true)
        .build()?;

    let state = Arc::new(AppState {
        client,
        proxy_to,
        substitutions,
        domain: config.domain.clone(),
    });

    // 4. Setup Router
    let app = Router::new()
        .route("/*path", any(handler))
        .route("/", any(handler))
        .layer(CompressionLayer::new())
        .layer(ValidateRequestHeaderLayer::basic(&auth_user, &auth_pass))
        .with_state(state);

    // 5. TLS Configuration
    debug!(
        "Loading TLS certificates from {} and {}",
        config.ssl_cert, config.ssl_key
    );
    let tls_config = RustlsConfig::from_pem_file(&config.ssl_cert, &config.ssl_key)
        .await
        .map_err(|e| {
            error!("Failed to load TLS certificates: {}", e);
            e
        })?;

    let addr: SocketAddr = config.listen_addr.parse().map_err(|e| {
        error!(
            "Failed to parse listen address '{}': {}",
            config.listen_addr, e
        );
        e
    })?;

    info!("HTTPS Proxy listening on {}", addr);

    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await
        .map_err(|e| {
            error!("Server error: {}", e);
            e
        })?;

    Ok(())
}

async fn handler(State(state): State<Arc<AppState>>, req: Request) -> Response {
    let method = req.method().clone();
    let uri = req.uri().clone();

    let host_header = req
        .headers()
        .get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");

    if host_header.is_empty() {
        warn!("Request received with missing or invalid Host header");
        return (StatusCode::BAD_REQUEST, "Missing Host header").into_response();
    }

    let space_host: Vec<&str> = host_header.split(&state.domain).collect();

    if space_host.len() != 2 {
        warn!(
            "Host header '{}' does not match domain suffix '{}'",
            host_header, state.domain
        );
        return (StatusCode::INTERNAL_SERVER_ERROR, "Invalid Host header").into_response();
    }

    let subdomain = space_host[0];
    let to_host = match state.proxy_to.get(subdomain) {
        Some(t) => t,
        None => {
            warn!("No mapping found for subdomain '{}'", subdomain);
            return (StatusCode::NOT_FOUND, "Subdomain not mapped").into_response();
        }
    };

    let scheme = if subdomain == WIKIDOT_SPACE_NAME {
        "https"
    } else {
        "http"
    };

    let path_query = uri.path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let target_url = format!("{}://{}{}", scheme, to_host, path_query);

    debug!(
        "Proxying request: {} {} -> {}",
        method, host_header, target_url
    );

    let mut headers = req.headers().clone();
    headers.remove(header::HOST);
    headers.remove(header::AUTHORIZATION);
    headers.remove(header::ACCEPT_ENCODING); // Let reqwest manage decompression

    let body_bytes = match axum::body::to_bytes(req.into_body(), 1024 * 1024 * 50).await {
        Ok(b) => b,
        Err(e) => {
            error!("Failed to read request body from client: {}", e);
            return (StatusCode::BAD_REQUEST, "Failed to read body").into_response();
        }
    };

    let proxy_req = state
        .client
        .request(method.clone(), &target_url)
        .headers(headers)
        .body(body_bytes);

    match proxy_req.send().await {
        Ok(resp) => {
            let status = resp.status();
            debug!("Upstream response received: {} for {}", status, target_url);

            let mut resp_headers = resp.headers().clone();

            let content_type = resp_headers
                .get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("text/plain");

            let is_text = content_type.starts_with("text/")
                || content_type.contains("javascript")
                || content_type.contains("json");

            let final_body = if is_text {
                match resp.text().await {
                    Ok(mut text) => {
                        debug!(
                            "Processing text response body ({} bytes) for rewriting",
                            text.len()
                        );
                        for (i, subst) in state.substitutions.iter().enumerate() {
                            let before = text.len();
                            text = subst.from.replace_all(&text, &subst.to).to_string();
                            let after = text.len();
                            if before != after {
                                debug!(
                                    "Substitution rule {} changed body size from {} to {}",
                                    i, before, after
                                );
                            }
                        }
                        Body::from(text)
                    }
                    Err(e) => {
                        error!("Failed to read upstream response body as text: {}", e);
                        Body::empty()
                    }
                }
            } else {
                match resp.bytes().await {
                    Ok(bytes) => Body::from(bytes),
                    Err(e) => {
                        error!("Failed to read upstream binary response body: {}", e);
                        Body::empty()
                    }
                }
            };

            // Process cookies
            let set_cookies: Vec<String> = resp_headers
                .get_all(header::SET_COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
                .collect();

            if !set_cookies.is_empty() {
                debug!("Rewriting {} cookies", set_cookies.len());
                resp_headers.remove(header::SET_COOKIE);
                for cookie in set_cookies {
                    let replaced = cookie.replace(".wikidot.com", &state.domain);
                    let new_val = format!("{}; SameSite=Lax", replaced);
                    if let Ok(v) = HeaderValue::from_str(&new_val) {
                        resp_headers.append(header::SET_COOKIE, v);
                    } else {
                        warn!(
                            "Failed to create HeaderValue for modified cookie: {}",
                            new_val
                        );
                    }
                }
            }

            // Rewrite Location headers
            if let Some(loc) = resp_headers.get(header::LOCATION) {
                if let Ok(loc_str) = loc.to_str() {
                    let mut new_loc = loc_str.to_string();
                    let mut changed = false;
                    for (proxy, target) in &state.proxy_to {
                        let original = format!("http://{}", target);
                        let replacement = format!("https://{}{}", proxy, state.domain);
                        if new_loc.contains(&original) {
                            new_loc = new_loc.replace(&original, &replacement);
                            changed = true;
                        }

                        let original_https = format!("https://{}", target);
                        if new_loc.contains(&original_https) {
                            new_loc = new_loc.replace(&original_https, &replacement);
                            changed = true;
                        }
                    }
                    if changed {
                        debug!(
                            "Rewriting Location header from '{}' to '{}'",
                            loc_str, new_loc
                        );
                        if let Ok(v) = HeaderValue::from_str(&new_loc) {
                            resp_headers.insert(header::LOCATION, v);
                        } else {
                            warn!(
                                "Failed to create HeaderValue for modified Location: {}",
                                new_loc
                            );
                        }
                    }
                }
            }

            let mut builder = Response::builder().status(status);
            *builder.headers_mut().unwrap() = resp_headers;
            builder.body(final_body).unwrap_or_else(|e| {
                error!("Failed to build response: {}", e);
                Response::builder()
                    .status(StatusCode::INTERNAL_SERVER_ERROR)
                    .body(Body::empty())
                    .unwrap()
            })
        }
        Err(e) => {
            error!("Upstream proxy error for {}: {}", target_url, e);
            (StatusCode::BAD_GATEWAY, format!("Upstream error: {}", e)).into_response()
        }
    }
}
