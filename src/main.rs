use arti_client::{config::BoolOrAuto, StreamPrefs, TorClient, TorClientConfig};
use http::{HeaderMap, HeaderName, HeaderValue};
use std::env;
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

async fn parse_headers(header_bytes: Vec<u8>) -> HeaderMap {
    let header_string = String::from_utf8_lossy(&header_bytes).to_string();
    let header_lines = header_string
        .split("\r\n")
        .filter(|line| line.contains(": "))
        .collect::<Vec<_>>();

    let mut headers = HeaderMap::new();
    for line in header_lines {
        let mut parts = line.splitn(2, ": ");
        let key = parts.next().unwrap();
        let value = parts.next().unwrap();
        headers.insert(
            HeaderName::from_bytes(key.as_bytes()).unwrap(),
            HeaderValue::from_str(value).unwrap(),
        );
    }

    headers
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
) -> Result<(String, HeaderMap), tokio::io::Error> {
    let header_bytes = read_until(stream, b"\r\n\r\n").await?;
    let header_string = String::from_utf8_lossy(&header_bytes).to_string();
    let (request_line, header_string) = header_string.split_once("\r\n").unwrap();
    let headers = parse_headers(header_string.as_bytes().to_vec()).await;

    Ok((request_line.to_string(), headers))
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
        let cut_chunk_size = String::from_utf8_lossy(&raw_chunk_size)[..raw_chunk_size.len() - 2].to_string();
        let chunk_size = usize::from_str_radix(&cut_chunk_size, 16).unwrap();

        // read chunk + CRLF
        let mut chunk = vec![0; chunk_size + 2];
        stream_in.read_exact(&mut chunk).await.unwrap();

        // write chunk + CRLF
        stream_out.write_all(&raw_chunk_size).await.unwrap();
        stream_out.write_all(&chunk).await.unwrap();

        // if chunk size is 0, end of body
        if chunk_size == 0 {
            break;
        }
    }

    Ok(())
}

async fn handler(state: AppState, stream: &mut TcpStream) -> Result<(), tokio::io::Error> {
    // read request
    let (request_line, mut headers) = read_header_data(stream).await.unwrap();

    // change host to onion
    let onion_host = headers
        .get("Host")
        .unwrap()
        .to_str()
        .unwrap()
        .split_once(".")
        .unwrap()
        .0
        .to_string()
        + &".onion".to_string();
    headers.insert("Host", HeaderValue::from_str(&onion_host).unwrap());

    // re-create header
    let header_bytes = headers_to_bytes(&mut headers.clone());

    // get tor stream
    let mut tor_stream = state
        .tor_client
        .connect_with_prefs(
            (onion_host, 80),
            StreamPrefs::new().connect_to_onion_services(BoolOrAuto::Explicit(true)),
        )
        .await
        .unwrap();

    // send request headers
    tor_stream
        .write_all(&request_line.as_bytes())
        .await
        .unwrap();
    tor_stream.write_all(b"\r\n").await.unwrap();
    tor_stream.write_all(&header_bytes).await.unwrap();
    tor_stream.write_all(b"\r\n").await.unwrap();
    tor_stream.flush().await.unwrap();

    // send body
    if headers
        .get("Transfer-Encoding")
        .is_some_and(|v| v.to_str().unwrap().to_lowercase() == "chunked")
    {
        forward_chunked_encoding(stream, &mut tor_stream).await?;
    } else if let Some(content_length) = headers.get("Content-Length") {
        let content_length = content_length.to_str().unwrap().parse::<usize>().unwrap();
        forward_content_length(stream, &mut tor_stream, content_length).await?;
    }
    tor_stream.flush().await.unwrap();

    // read response
    let (status_line, headers) = read_header_data(&mut tor_stream).await.unwrap();

    // re-create header
    let header_bytes = headers_to_bytes(&mut headers.clone());

    // write response
    stream.write_all(&status_line.as_bytes()).await.unwrap();
    stream.write_all(b"\r\n").await.unwrap();
    stream.write_all(&header_bytes).await.unwrap();
    stream.write_all(b"\r\n").await.unwrap();
    stream.flush().await.unwrap();

    // write body
    if headers
        .get("Transfer-Encoding")
        .is_some_and(|v| v.to_str().unwrap().to_lowercase() == "chunked")
    {
        forward_chunked_encoding(&mut tor_stream, stream).await?;
    } else if let Some(content_length) = headers.get("Content-Length") {
        let content_length = content_length.to_str().unwrap().parse::<usize>().unwrap();
        forward_content_length(&mut tor_stream, stream, content_length).await?;
    }
    stream.flush().await.unwrap();

    Ok(())
}

#[derive(Clone)]
struct AppState {
    tor_client: TorClient<PreferredRuntime>,
}

#[tokio::main]
async fn main() {
    let port = env::var("PORT").unwrap_or("3000".to_string());
    let host = env::var("HOST").unwrap_or("0.0.0.0".to_string());
    let addr = format!("{}:{}", host, port);

    let config = TorClientConfig::default();
    let tor_client =
        TorClient::isolated_client(&TorClient::create_bootstrapped(config).await.unwrap());
    let state = AppState { tor_client };

    let listerner = TcpListener::bind(&addr).await.unwrap();
    println!("Listening at {}", addr);

    loop {
        let (mut stream, _) = listerner.accept().await.unwrap();
        let state = state.clone();
        tokio::spawn(async move {
            handler(state, &mut stream).await.ok();
        });
    }
}
