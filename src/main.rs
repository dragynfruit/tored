use arti_client::{config::BoolOrAuto, DataStream, StreamPrefs, TorClient, TorClientConfig};
use cookie::CookieJar;
use http::{HeaderMap, HeaderName, HeaderValue};
use std::{env, error::Error};
use tokio::{
    io::{AsyncRead, AsyncReadExt, AsyncWriteExt},
    net::{TcpListener, TcpStream},
};
use tor_rtcompat::PreferredRuntime;

async fn read_until<W: AsyncRead + Unpin>(
    stream: &mut W,
    delim: &[u8],
) -> Result<Vec<u8>, tokio::io::Error> {
    let mut buf = Vec::new();
    let mut delim_idx = 0;
    let mut read_buf = [0; 1];
    loop {
        stream.read_exact(&mut read_buf).await?;
        buf.push(read_buf[0]);
        if read_buf[0] == delim[delim_idx] {
            delim_idx += 1;
            if delim_idx == delim.len() {
                break;
            }
        } else {
            delim_idx = 0;
        }
    }
    Ok(buf)
}

async fn parse_headers(header_bytes: Vec<u8>) -> (HeaderMap, CookieJar) {
    let header_string = String::from_utf8_lossy(&header_bytes).to_string();
    let header_lines = header_string
        .split("\r\n")
        .filter(|line| line.contains(": "))
        .collect::<Vec<_>>();

    let mut headers = HeaderMap::new();
    let mut cookies = CookieJar::new();
    for line in header_lines {
        let mut parts = line.splitn(2, ": ");
        let key = parts.next().unwrap();
        let value = parts.next().unwrap();

        if key.to_lowercase() == "set-cookie" {
            cookies.add_original(value.to_string());
        } else {
            headers.insert(
                HeaderName::from_bytes(key.as_bytes()).unwrap(),
                HeaderValue::from_str(value).unwrap(),
            );
        }
    }

    (headers, cookies)
}

fn headers_to_bytes(headers: &mut HeaderMap) -> Vec<u8> {
    headers.drain().fold(Vec::new(), |mut acc, (key, value)| {
        acc.extend_from_slice(key.unwrap().as_str().as_bytes());
        acc.extend_from_slice(b": ");
        acc.extend_from_slice(value.as_bytes());
        acc.extend_from_slice(b"\r\n");
        acc
    })
}

async fn read_header_data<R: AsyncRead + Unpin>(
    stream: &mut R,
) -> Result<(String, HeaderMap, CookieJar), tokio::io::Error> {
    let header_bytes = read_until(stream, b"\r\n\r\n").await?;
    let header_string = String::from_utf8_lossy(&header_bytes).to_string();
    let (request_line, header_string) = header_string.split_once("\r\n").unwrap();
    let (headers, cookies) = parse_headers(header_string.as_bytes().to_vec()).await;

    Ok((request_line.to_string(), headers, cookies))
}

async fn forward_content_length<R: AsyncRead + Unpin, W: AsyncWriteExt + Unpin>(
    stream_in: &mut R,
    stream_out: &mut W,
    content_length: usize,
) -> Result<(), tokio::io::Error> {
    let mut chunk = vec![0; 2048];
    let mut sent_bytes = 0;
    while sent_bytes < content_length {
        let read_bytes = stream_in.read(&mut chunk).await?;
        stream_out.write_all(&chunk[..read_bytes]).await?;
        sent_bytes += read_bytes;
    }

    Ok(())
}

async fn forward_chunked_encoding<R: AsyncRead + Unpin, W: AsyncWriteExt + Unpin>(
    stream_in: &mut R,
    stream_out: &mut W,
) -> Result<(), tokio::io::Error> {
    loop {
        // read chunk size
        let raw_chunk_size = read_until(stream_in, b"\r\n").await?;
        let cut_chunk_size =
            String::from_utf8_lossy(&raw_chunk_size)[..raw_chunk_size.len() - 2].to_string();
        let chunk_size = usize::from_str_radix(&cut_chunk_size, 16).unwrap();

        // read chunk + CRLF
        let mut chunk = vec![0; chunk_size + 2];
        stream_in.read_exact(&mut chunk).await?;

        // write chunk + CRLF
        stream_out.write_all(&raw_chunk_size).await?;
        stream_out.write_all(&chunk).await?;

        // if chunk size is 0, end of body
        if chunk_size == 0 {
            break;
        }
    }

    Ok(())
}

async fn forward_body<R: AsyncRead + Unpin, W: AsyncWriteExt + Unpin>(
    stream_in: &mut R,
    stream_out: &mut W,
    headers: &HeaderMap,
) -> Result<(), tokio::io::Error> {
    if headers
        .get("Transfer-Encoding")
        .is_some_and(|v| v.to_str().unwrap().to_lowercase() == "chunked")
    {
        forward_chunked_encoding(stream_in, stream_out).await?;
    } else if let Some(content_length) = headers.get("Content-Length") {
        let content_length = content_length.to_str().unwrap().parse::<usize>().unwrap();
        forward_content_length(stream_in, stream_out, content_length).await?;
    }

    Ok(())
}

async fn cookies_to_bytes(cookies: &CookieJar) -> Vec<u8> {
    let mut cookie_bytes = Vec::new();
    for cookie in cookies.iter() {
        cookie_bytes.extend_from_slice(b"Set-Cookie: ");
        cookie_bytes.extend_from_slice(cookie.to_string().as_bytes());
        cookie_bytes.extend_from_slice(b"\r\n");
    }

    cookie_bytes
}

async fn handler(
    state: AppState,
    stream: &mut TcpStream,
    public_host: &String,
) -> Result<(), Box<dyn Error>> {
    let mut kept_tor_stream: Option<DataStream> = None;

    loop {
        // read request
        let (request_line, mut request_headers, _) = match read_header_data(stream).await {
            Ok(data) => data,
            Err(err) => {
                if err.kind() == tokio::io::ErrorKind::UnexpectedEof {
                    log::debug!("Client closed connection");
                }
                return Err(Box::new(err));
            }
        };
        log::trace!("Read request: {}", request_line);

        // Send blank page
        if request_headers.get("Host").is_none()
            || request_headers
                .get("Host")
                .unwrap()
                .to_str()?
                .starts_with(public_host)
        {
            log::debug!("Sending blank page");
            stream.write_all("HTTP/1.1 200 OK\r\nContent-Length: 5\r\n\r\nHello".as_bytes()).await?;
            stream.flush().await?;
        }

        // change host to onion
        let onion_host = request_headers
            .get("Host")
            .unwrap()
            .to_str()?
            .split_once(format!(".{public_host}").as_str())
            .unwrap()
            .0
            .to_string()
            + &".onion".to_string();
        request_headers.insert("Host", HeaderValue::from_str(&onion_host)?);
        request_headers.remove("Referer");
        log::trace!("Changed host to: {}", onion_host);

        // re-create header
        let header_bytes = headers_to_bytes(&mut request_headers.clone());
        log::trace!("Recreated headers");

        // get tor stream if it is not created
        if kept_tor_stream.is_none() {
            log::trace!("Creating tor stream");
            let tor_stream = state
                .tor_client
                .connect_with_prefs(
                    (onion_host.clone(), 80),
                    StreamPrefs::new().connect_to_onion_services(BoolOrAuto::Explicit(true)),
                )
                .await;

            if tor_stream.is_err() {
                log::warn!("Failed to create tor stream");
                stream
                    .write_all(b"HTTP/1.1 502 Bad Gateway\r\nContent-Length: 11\r\n\r\nBad Gateway")
                    .await?;
                stream.flush().await?;
                break;
            }

            log::trace!("Tor stream created");
            kept_tor_stream = Some(tor_stream.unwrap());
        }
        let mut tor_stream = kept_tor_stream.as_mut().unwrap();
        log::trace!("Got tor stream");

        // send request headers
        tor_stream.write_all(&request_line.as_bytes()).await?;
        tor_stream.write_all(b"\r\n").await?;
        tor_stream.write_all(&header_bytes).await?;
        tor_stream.write_all(b"\r\n").await?;
        tor_stream.flush().await?;
        log::trace!("Sent request headers");

        // send body
        forward_body(stream, &mut tor_stream, &request_headers).await?;
        tor_stream.flush().await?;
        log::trace!("Sent body");

        // read response
        let (status_line, mut response_headers, mut cookies) =
            read_header_data(&mut tor_stream).await?;
        log::trace!("Read response: {}", status_line);

        // read response code from status line
        let status_code = status_line
            .split_whitespace()
            .nth(1)
            .unwrap()
            .parse::<u16>()?;
        log::trace!("Status code: {}", status_code);

        // if it is a redirect, change location to host. If it is not a .onion return warning to user
        if status_code / 100 == 3 {
            log::trace!("Got a redirect");
            if let Some(location) = response_headers.get("Location") {
                let location = location.to_str()?;
                let is_onion = location
                    .replace("http://", "")
                    .replace("https://", "")
                    .split("/")
                    .next()
                    .unwrap()
                    .ends_with(".onion");

                if is_onion {
                    log::trace!("Redirecting to tored onion");
                    let new_location = location.replace(".onion", &format!(".{}", public_host));
                    response_headers
                        .insert("Location", HeaderValue::from_str(&new_location).unwrap());
                } else {
                    log::trace!("Trying to redirect to non-onion");
                    let response = format!(
                        "HTTP/1.1 200 OK\r\nContent-Length: {}\r\n\r\n{}",
                        location.len(),
                        location
                    );
                    stream.write_all(response.as_bytes()).await?;
                    stream.flush().await?;
                    break;
                }
            }
        }

        // rewrite all cookies
        for cookie in cookies.clone().iter() {
            if let Some(domain) = cookie.domain() {
                if domain.ends_with(".onion") {
                    let new_domain = domain.replace(".onion", &format!(".{}", public_host));

                    let mut updated_cookie = cookie.clone();
                    updated_cookie.set_domain(new_domain);

                    cookies.add(updated_cookie);
                }
            }
        }
        log::trace!("Rewrote cookies");

        // re-create header
        let mut header_bytes = headers_to_bytes(&mut response_headers.clone());
        header_bytes.append(&mut cookies_to_bytes(&cookies).await);
        log::trace!("Recreated headers");

        // write response
        stream.write_all(&status_line.as_bytes()).await?;
        stream.write_all(b"\r\n").await?;
        stream.write_all(&header_bytes).await?;
        stream.write_all(b"\r\n").await?;
        stream.flush().await?;
        log::trace!("Sent response");

        // write body
        forward_body(&mut tor_stream, stream, &response_headers).await?;
        stream.flush().await?;
        log::trace!("Sent body");

        // keep alive
        let request_keep_alive = request_headers
            .get("Connection")
            .is_some_and(|v| v.to_str().unwrap().to_lowercase() == "keep-alive");
        let response_keep_alive = response_headers
            .get("Connection")
            .is_some_and(|v| v.to_str().unwrap().to_lowercase() == "keep-alive");

        if !request_keep_alive || !response_keep_alive {
            log::trace!("Closing connection");
            break;
        }

        log::trace!("Keeping connection alive");
    }

    log::debug!("Shutting down streams");
    stream.shutdown().await.ok();
    if kept_tor_stream.is_some() {
        kept_tor_stream.unwrap().shutdown().await.ok();
    }

    log::debug!("Handler finished");
    Ok(())
}

#[derive(Clone)]
struct AppState {
    tor_client: TorClient<PreferredRuntime>,
}

#[tokio::main]
async fn main() {
    env_logger::Builder::from_env(env_logger::Env::default().default_filter_or("info")).init();

    let port = env::var("PORT").unwrap_or("3000".to_string());
    let host = env::var("HOST").unwrap_or("0.0.0.0".to_string());
    let public_host = env::var("VIRTUAL_HOST")
        .unwrap_or(env::var("PUBLIC_HOST").unwrap_or("localhost".to_string()));
    let addr = format!("{}:{}", host, port);
    log::info!("Public host: {}", public_host);

    log::info!("Starting arti client");
    let config = TorClientConfig::default();
    let tor_client =
        TorClient::create_bootstrapped(config).await.unwrap_or_else(|_| {
            panic!("Failed to create tor client");
        });
    let state = AppState { tor_client };
    log::info!("Arti client started");

    let listerner = TcpListener::bind(&addr).await.unwrap_or_else(|_| {
        panic!("Failed to bind to address: {}", addr);
    });
    log::info!("Listening at {}", addr);

    loop {
        let accept = listerner.accept().await;
        if accept.is_err() {
            log::warn!("Failed to accept connection");
            continue;
        }
        let (mut stream, _) = accept.unwrap();
        log::debug!("Accepted connection");

        let (state, public_host) = (state.clone(), public_host.clone());
        log::trace!("Spawning handler");
        tokio::spawn(async move {
            let response = handler(state, &mut stream, &public_host).await;
            if response.is_err() {
                log::warn!("Failed to handle request: {:?}", response.err());
            }
        });
        log::trace!("Handler spawned");
    }
}
