use std::net::SocketAddr;
use std::sync::Arc;
use tokio::net::TcpListener;
use tauri::{AppHandle, Emitter, Manager};
use hyper::server::conn::http1;
use hyper::service::service_fn;
use hyper::{Request, Response, StatusCode, Method};
use hyper::body::Incoming;
use hyper_util::rt::TokioIo;
use http_body_util::{Full, BodyExt, combinators::BoxBody};
use bytes::Bytes;
use tokio_rustls::rustls::ServerConfig;
use tokio_rustls::TlsAcceptor;
use hyper_util::client::legacy::Client;
use hyper_rustls::HttpsConnectorBuilder;
use crate::proxy::ca::CaManager;

type ProxyBody = BoxBody<Bytes, hyper::Error>;

fn full<T: Into<Bytes>>(chunk: T) -> ProxyBody {
    Full::new(chunk.into())
        .map_err(|never| match never {})
        .boxed()
}

#[tauri::command]
pub async fn run_proxy_server(app: AppHandle, port: u16) -> Result<(), String> {
    let addr = SocketAddr::from(([0, 0, 0, 0], port));
    let listener = TcpListener::bind(addr).await.map_err(|e| e.to_string())?;

    println!("Proxy Listening on {}", addr);
    app.emit("proxy-status", format!("Running on {}", addr)).unwrap_or(());

    let app_dir = app.path().app_data_dir().unwrap_or(std::path::PathBuf::from("."));
    let ca_manager = Arc::new(CaManager::new(&app_dir).map_err(|e| e.to_string())?);

    tauri::async_runtime::spawn(async move {
        loop {
            if let Ok((stream, _)) = listener.accept().await {
                let io = TokioIo::new(stream);
                let app_handle = app.clone();
                let ca = ca_manager.clone();
                
                tokio::spawn(async move {
                    if let Err(_) = http1::Builder::new()
                        .serve_connection(io, service_fn(move |req| proxy_handler(req, app_handle.clone(), ca.clone())))
                        .with_upgrades()
                        .await
                    {
                        // networking errors are common, just ignore
                    }
                });
            }
        }
    });

    Ok(())
}

async fn proxy_handler(
    req: Request<Incoming>,
    app: AppHandle,
    ca: Arc<CaManager>
) -> Result<Response<ProxyBody>, hyper::Error> {
    if req.method() == Method::CONNECT {
        if let Some(host) = req.uri().authority().map(|a| a.to_string()) {
            tokio::spawn(async move {
                match hyper::upgrade::on(req).await {
                    Ok(upgraded) => {
                        if let Err(e) = handle_tunnel(upgraded, host, app, ca).await {
                             eprintln!("Tunnel error: {}", e);
                        }
                    }
                    Err(e) => eprintln!("Upgrade error: {}", e),
                }
            });
            return Ok(Response::new(full("")));
        } else {
             return Ok(Response::builder()
                .status(StatusCode::BAD_REQUEST)
                .body(full("CONNECT must have authority"))
                .unwrap());
        }
    } else {
        // Simple HTTP Proxy (not strictly required for HTTPS MITM but good to have)
         Ok(Response::new(full("DeepSide: Plain HTTP not supported, use HTTPS")))
    }
}

async fn handle_tunnel(
    upgraded: hyper::upgrade::Upgraded,
    host_addr: String,
    app: AppHandle,
    ca: Arc<CaManager>
) -> Result<(), String> {
    let domain = host_addr.split(':').next().unwrap_or(&host_addr);
    
    // Generate Fake Cert
    let (cert_der, key_der) = ca.generate_cert(domain).map_err(|e| format!("CA Gen error: {}", e))?;
    
    let certs = vec![tokio_rustls::rustls::pki_types::CertificateDer::from(cert_der)];
    let key = tokio_rustls::rustls::pki_types::PrivateKeyDer::Pkcs8(
        tokio_rustls::rustls::pki_types::PrivatePkcs8KeyDer::from(key_der)
    );

    let mut server_config = ServerConfig::builder()
        .with_no_client_auth()
        .with_single_cert(certs, key)
        .map_err(|e| e.to_string())?;
        
    server_config.alpn_protocols = vec![b"h2".to_vec(), b"http/1.1".to_vec()];
    let tls_acceptor = TlsAcceptor::from(Arc::new(server_config));

    // TLS Handshake with Client
    let tls_stream = tls_acceptor.accept(TokioIo::new(upgraded)).await.map_err(|e| e.to_string())?;

    // Serve Inner HTTP
    let service = service_fn(move |req| {
        mitm_service(req, host_addr.clone(), app.clone())
    });

    if let Err(_e) = http1::Builder::new()
        .serve_connection(TokioIo::new(tls_stream), service)
        .await 
    {
        // Connection closed
    }
    Ok(())
}

async fn mitm_service(
    req: Request<Incoming>,
    host_addr: String,
    app: AppHandle
) -> Result<Response<ProxyBody>, hyper::Error> {
    let uri = req.uri().to_string();
    let method = req.method().to_string();
    
    // Log Intercepted Traffic
    app.emit("proxy-log", format!("{} https://{}{}", method, host_addr, uri)).unwrap_or(());

    // Prepare Upstream Client
    let https = HttpsConnectorBuilder::new()
        .with_native_roots().unwrap()
        .https_or_http()
        .enable_http1()
        .enable_http2()
        .build();

    let client = Client::builder(hyper_util::rt::TokioExecutor::new())
        .build(https);

    let mut builder = Request::builder()
        .method(req.method())
        .version(req.version());
        
    for (k, v) in req.headers() {
        // Filter some headers if needed, but keeping all is fine for transparency
        builder = builder.header(k, v);
    }
    
    let upstream_uri = format!("https://{}{}", host_addr, uri);
    
    // We consume the request body here. 
    // Ideally we would stream it, but for stability we just pass it (Hyper handles Incoming -> Upstream Request Body usually)
    let upstream_req = builder.uri(upstream_uri)
        .body(req.into_body())
        .expect("request builder failed");

    match client.request(upstream_req).await {
        Ok(res) => {
            let (parts, body) = res.into_parts();
            
            // BUFFERING THE RESPONSE BODY
            // This is the critical fix to ensure we have a sized Body type (Bytes)
            // instead of dealing with complex stream lifetimes.
            use http_body_util::BodyExt; // Import here to be safe
            
            match body.collect().await {
                Ok(collected) => {
                    let bytes = collected.to_bytes();
                    Ok(Response::from_parts(parts, full(bytes)))
                },
                Err(e) => {
                    eprintln!("Failed to read upstream body: {}", e);
                    Ok(Response::builder()
                        .status(StatusCode::BAD_GATEWAY)
                        .body(full("DeepSide: Failed to read from server"))
                        .unwrap())
                }
            }
        },
        Err(e) => {
             eprintln!("Upstream connection failed: {}", e);
             Ok(Response::builder()
                .status(StatusCode::BAD_GATEWAY)
                .body(full(format!("DeepSide Proxy Error: {}", e)))
                .unwrap())
        }
    }
}
