use axum::{
    body::Body,
    extract::{Request, State},
    http::{HeaderValue, header, StatusCode},
    response::{Response, IntoResponse},
    routing::any,
    Router,
};
use axum_server::tls_rustls::RustlsConfig;
use reqwest::{Client, Proxy};
use regex::Regex;
use std::collections::HashMap;
use std::sync::Arc;
use std::net::SocketAddr;
use tower_http::validate_request::ValidateRequestHeaderLayer;
use serde::Deserialize;
use std::fs;

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

    // Fix for "Could not automatically determine the process-level CryptoProvider"
    rustls::crypto::ring::default_provider()
        .install_default()
        .expect("Failed to install rustls crypto provider");

    // Load config from file
    let config_path = std::env::args().nth(1).unwrap_or_else(|| "config.toml".to_string());
    let config_str = fs::read_to_string(&config_path)?;
    let config: Config = toml::from_str(&config_str)?;

    // Load secrets from ENV
    let auth_user = std::env::var("PROXY_USER").expect("PROXY_USER must be set");
    let auth_pass = std::env::var("PROXY_PASS").expect("PROXY_PASS must be set");

    // 1. Setup mappings
    let mut proxy_to = HashMap::new();
    proxy_to.insert(WIKIDOT_SPACE_NAME.to_string(), "www.wikidot.com".to_string());
    
    for (proxy, target) in &config.proxy_to_raw {
        proxy_to.insert(proxy.clone(), format!("{}.wikidot.com", target));
        proxy_to.insert(format!("files.{}", proxy), format!("{}.wdfiles.com", target));
    }

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

    // 3. Configure Reqwest with Upstream Proxy
    let client = Client::builder()
        .proxy(Proxy::all(&config.upstream_proxy)?)
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
        .layer(ValidateRequestHeaderLayer::basic(&auth_user, &auth_pass))
        .with_state(state);

    // 5. TLS Configuration
    let tls_config = RustlsConfig::from_pem_file(&config.ssl_cert, &config.ssl_key).await?;

    let addr: SocketAddr = config.listen_addr.parse()?;
    println!("HTTPS Proxy listening on {}", addr);

    axum_server::bind_rustls(addr, tls_config)
        .serve(app.into_make_service())
        .await?;

    Ok(())
}

async fn handler(
    State(state): State<Arc<AppState>>,
    req: Request,
) -> Response {
    let host_header = req.headers().get(header::HOST)
        .and_then(|h| h.to_str().ok())
        .unwrap_or("");
    
    let space_host: Vec<&str> = host_header.split(&state.domain).collect();
    
    if space_host.len() != 2 {
        return (StatusCode::INTERNAL_SERVER_ERROR, "Invalid Host header").into_response();
    }

    let subdomain = space_host[0];
    let to_host = match state.proxy_to.get(subdomain) {
        Some(t) => t,
        None => return (StatusCode::NOT_FOUND, "Subdomain not mapped").into_response(),
    };

    let scheme = if subdomain == WIKIDOT_SPACE_NAME { "https" } else { "http" };
    let path_query = req.uri().path_and_query().map(|pq| pq.as_str()).unwrap_or("/");
    let target_url = format!("{}://{}{}", scheme, to_host, path_query);
    
    let method = req.method().clone();
    let mut headers = req.headers().clone();
    headers.remove(header::HOST); 
    headers.remove(header::AUTHORIZATION);
    
    let body_bytes = axum::body::to_bytes(req.into_body(), 1024 * 1024 * 50).await; 
    let body = match body_bytes {
        Ok(b) => b,
        Err(_) => return (StatusCode::BAD_REQUEST, "Failed to read body").into_response(),
    };

    let proxy_req = state.client.request(method, &target_url)
        .headers(headers)
        .body(body);
        
    match proxy_req.send().await {
        Ok(resp) => {
            let status = resp.status();
            let mut resp_headers = resp.headers().clone();
            
            let content_type = resp_headers.get(header::CONTENT_TYPE)
                .and_then(|v| v.to_str().ok())
                .unwrap_or("text/plain");
            
            let is_text = content_type.starts_with("text/") 
                || content_type.contains("javascript") 
                || content_type.contains("json");

            let final_body = if is_text {
                match resp.text().await {
                   Ok(mut text) => {
                       for subst in &state.substitutions {
                           text = subst.from.replace_all(&text, &subst.to).to_string();
                       }
                       Body::from(text)
                   },
                   Err(_) => Body::empty(),
                }
            } else {
                let bytes = resp.bytes().await.unwrap_or_default();
                Body::from(bytes)
            };

            let set_cookies: Vec<String> = resp_headers.get_all(header::SET_COOKIE)
                .iter()
                .filter_map(|v| v.to_str().ok().map(|s| s.to_string()))
                .collect();
                
            resp_headers.remove(header::SET_COOKIE);
            
            for cookie in set_cookies {
                let replaced = cookie.replace(".wikidot.com", &state.domain);
                let new_val = format!("{}; SameSite=Lax", replaced);
                if let Ok(v) = HeaderValue::from_str(&new_val) {
                    resp_headers.append(header::SET_COOKIE, v);
                }
            }

            if let Some(loc) = resp_headers.get(header::LOCATION) {
                if let Ok(loc_str) = loc.to_str() {
                    let mut new_loc = loc_str.to_string();
                    for (proxy, target) in &state.proxy_to {
                        let original = format!("http://{}", target);
                        let replacement = format!("https://{}{}", proxy, state.domain);
                        new_loc = new_loc.replace(&original, &replacement);
                        
                        let original_https = format!("https://{}", target);
                        new_loc = new_loc.replace(&original_https, &replacement);
                    }
                    if let Ok(v) = HeaderValue::from_str(&new_loc) {
                        resp_headers.insert(header::LOCATION, v);
                    }
                }
            }

            let mut builder = Response::builder().status(status);
            *builder.headers_mut().unwrap() = resp_headers;
            builder.body(final_body).unwrap_or_else(|_| Response::new(Body::empty()))
        }
        Err(e) => {
            eprintln!("Proxy error: {}", e);
            (StatusCode::BAD_GATEWAY, format!("Upstream error: {}", e)).into_response()
        }
    }
}
