//! Минимальный многопоточный HTTP-сервер на std.

use std::io::{Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::Arc;
use std::time::Duration;

pub struct Req {
    pub method: String,
    pub path: String,
    pub body: String,
    /// Заголовок Origin, если браузер его прислал. Нужен, чтобы чужая страница
    /// не могла дёргать локальный API (CSRF/DNS-rebinding).
    pub origin: Option<String>,
}

pub enum Body {
    Json(String),
    /// Ответ с ошибкой: статус и текст, который увидит интерфейс.
    Error(u16, String),
    File(Vec<u8>, &'static str),
    NotFound,
}

#[cfg_attr(not(test), allow(dead_code))]
pub fn serve<F>(port: u16, handler: F)
where
    F: Fn(&Req) -> Body + Send + Sync + 'static,
{
    match bind(port) {
        Ok(listener) => serve_on(listener, handler),
        Err(e) => {
            eprintln!("{e}");
            std::process::exit(1);
        }
    }
}

/// Занимает порт заранее.
///
/// Нужно, чтобы отличить «порт занят другим приложением» от «наше приложение
/// уже запущено»: во втором случае достаточно открыть окно к работающему
/// экземпляру, а не падать.
pub fn bind(port: u16) -> Result<TcpListener, String> {
    TcpListener::bind(("127.0.0.1", port))
        .map_err(|e| format!("Не удалось занять порт {port}: {e}"))
}

/// Обслуживает запросы на уже занятом порту.
pub fn serve_on<F>(listener: TcpListener, handler: F)
where
    F: Fn(&Req) -> Body + Send + Sync + 'static,
{
    let handler = Arc::new(handler);
    for stream in listener.incoming() {
        match stream {
            Ok(s) => {
                let h = Arc::clone(&handler);
                std::thread::spawn(move || {
                    let _ = handle(s, &*h);
                });
            }
            Err(_) => continue,
        }
    }
}

fn handle<F>(mut stream: TcpStream, handler: &F) -> std::io::Result<()>
where
    F: Fn(&Req) -> Body,
{
    stream.set_read_timeout(Some(Duration::from_secs(10)))?;
    let mut buf = Vec::with_capacity(8192);
    let mut chunk = [0u8; 4096];
    let header_end;
    loop {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            return Ok(());
        }
        buf.extend_from_slice(&chunk[..n]);
        if let Some(pos) = find_header_end(&buf) {
            header_end = pos;
            break;
        }
        if buf.len() > 64 * 1024 {
            return Ok(());
        }
    }

    let head = String::from_utf8_lossy(&buf[..header_end]).to_string();
    let mut lines = head.lines();
    let request_line = lines.next().unwrap_or("");
    let mut parts = request_line.split_whitespace();
    let method = parts.next().unwrap_or("GET").to_string();
    let raw_path = parts.next().unwrap_or("/").to_string();

    let mut content_length = 0usize;
    let mut origin: Option<String> = None;
    for line in lines {
        let lower = line.to_lowercase();
        if let Some(v) = lower.strip_prefix("content-length:") {
            content_length = v.trim().parse().unwrap_or(0);
        } else if let Some(v) = lower.strip_prefix("origin:") {
            origin = Some(v.trim().to_string());
        }
    }

    let body_start = header_end + 4;
    let mut body_bytes = if buf.len() > body_start {
        buf[body_start..].to_vec()
    } else {
        Vec::new()
    };
    while body_bytes.len() < content_length {
        let n = stream.read(&mut chunk)?;
        if n == 0 {
            break;
        }
        body_bytes.extend_from_slice(&chunk[..n]);
    }
    let body = String::from_utf8_lossy(&body_bytes).to_string();

    let path = raw_path.split('?').next().unwrap_or("/").to_string();
    let query = raw_path
        .split_once('?')
        .map(|(_, q)| q.to_string())
        .unwrap_or_default();

    let req = Req {
        method,
        path: if query.is_empty() {
            path
        } else {
            format!("{path}?{query}")
        },
        body,
        origin,
    };

    let resp = handler(&req);
    match resp {
        Body::Json(text) => write_response(&mut stream, 200, "application/json; charset=utf-8", text.as_bytes()),
        Body::Error(status, text) => {
            write_response(&mut stream, status, "application/json; charset=utf-8", text.as_bytes())
        }
        Body::File(bytes, mime) => write_response(&mut stream, 200, mime, &bytes),
        Body::NotFound => write_response(
            &mut stream,
            404,
            "application/json; charset=utf-8",
            br#"{"error":"not found"}"#,
        ),
    }
}

fn write_response(
    stream: &mut TcpStream,
    status: u16,
    mime: &str,
    body: &[u8],
) -> std::io::Result<()> {
    // Текст статуса должен соответствовать коду: «404 OK» — это неправда.
    let reason = match status {
        200 => "OK",
        400 => "Bad Request",
        403 => "Forbidden",
        404 => "Not Found",
        500 => "Internal Server Error",
        _ => "Unknown",
    };
    let head = format!(
        "HTTP/1.1 {status} {reason}\r\nContent-Type: {mime}\r\nContent-Length: {}\r\nCache-Control: no-store\r\nAccess-Control-Allow-Origin: *\r\nConnection: close\r\n\r\n",
        body.len()
    );
    stream.write_all(head.as_bytes())?;
    stream.write_all(body)?;
    stream.flush()
}

fn find_header_end(buf: &[u8]) -> Option<usize> {
    buf.windows(4).position(|w| w == b"\r\n\r\n")
}

pub fn mime_for(path: &str) -> &'static str {
    let ext = path.rsplit('.').next().unwrap_or("").to_lowercase();
    match ext.as_str() {
        "html" => "text/html; charset=utf-8",
        "js" => "text/javascript; charset=utf-8",
        "css" => "text/css; charset=utf-8",
        "json" => "application/json; charset=utf-8",
        "png" => "image/png",
        "jpg" | "jpeg" => "image/jpeg",
        "svg" => "image/svg+xml",
        "ico" => "image/x-icon",
        "woff2" => "font/woff2",
        "woff" => "font/woff",
        _ => "application/octet-stream",
    }
}
