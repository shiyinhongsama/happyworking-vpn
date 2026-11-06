use happyworking_vpn_core::{ErrorCode, VpnError};

pub struct HttpResponse {
    pub status: u16,
    headers: Vec<(String, String)>,
    pub body: Vec<u8>,
}

impl HttpResponse {
    pub(crate) fn from_body(body: &[u8]) -> Self {
        Self {
            status: 200,
            headers: Vec::new(),
            body: body.to_vec(),
        }
    }

    pub fn parse(input: &[u8], max_size: usize) -> Result<Self, VpnError> {
        if input.len() > max_size {
            return Err(protocol_error("HTTP 响应超过大小限制"));
        }

        let mut header_buffer = [httparse::EMPTY_HEADER; 64];
        let mut response = httparse::Response::new(&mut header_buffer);
        let header_end = match response.parse(input) {
            Ok(httparse::Status::Complete(size)) => size,
            Ok(httparse::Status::Partial) => {
                return Err(protocol_error("HTTP 响应头不完整"));
            }
            Err(_) => return Err(protocol_error("HTTP 响应格式无效")),
        };

        let status = response
            .code
            .ok_or_else(|| protocol_error("HTTP 缺少状态码"))?;
        let mut headers = Vec::with_capacity(response.headers.len());
        for header in response.headers {
            let value = std::str::from_utf8(header.value)
                .map_err(|_| protocol_error("HTTP 响应头不是有效 UTF-8"))?;
            headers.push((header.name.to_owned(), value.to_owned()));
        }

        let body_bytes = &input[header_end..];
        let content_length = header_value(&headers, "content-length");
        let chunked = header_value(&headers, "transfer-encoding")
            .is_some_and(|value| value.trim().eq_ignore_ascii_case("chunked"));

        if content_length.is_some() && chunked {
            return Err(protocol_error("HTTP 同时包含 Content-Length 和 chunked"));
        }

        let body = if let Some(length) = content_length {
            let length = length
                .trim()
                .parse::<usize>()
                .map_err(|_| protocol_error("HTTP Content-Length 无效"))?;
            if length > max_size || body_bytes.len() != length {
                return Err(protocol_error("HTTP Content-Length 与响应体不一致"));
            }
            body_bytes.to_vec()
        } else if chunked {
            decode_chunked(body_bytes, max_size)?
        } else {
            body_bytes.to_vec()
        };

        Ok(Self {
            status,
            headers,
            body,
        })
    }

    pub fn header(&self, name: &str) -> Option<&str> {
        self.headers
            .iter()
            .find(|(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }

    pub(crate) fn headers<'a>(&'a self, name: &'a str) -> impl Iterator<Item = &'a str> {
        self.headers
            .iter()
            .filter(move |(header, _)| header.eq_ignore_ascii_case(name))
            .map(|(_, value)| value.as_str())
    }
}

fn decode_chunked(mut input: &[u8], max_size: usize) -> Result<Vec<u8>, VpnError> {
    let mut output = Vec::new();
    loop {
        let line_end = find_crlf(input).ok_or_else(|| protocol_error("chunked 行不完整"))?;
        let size_text = std::str::from_utf8(&input[..line_end])
            .map_err(|_| protocol_error("chunked 长度不是文本"))?;
        let size_text = size_text.split(';').next().unwrap_or_default().trim();
        let size =
            usize::from_str_radix(size_text, 16).map_err(|_| protocol_error("chunked 长度无效"))?;
        input = &input[line_end + 2..];

        if size == 0 {
            if input.starts_with(b"\r\n") {
                if input.len() != 2 {
                    return Err(protocol_error("chunked 响应包含多余数据"));
                }
                return Ok(output);
            }
            let trailer_end =
                find_double_crlf(input).ok_or_else(|| protocol_error("chunked trailer 不完整"))?;
            if trailer_end + 4 != input.len() {
                return Err(protocol_error("chunked 响应包含多余数据"));
            }
            return Ok(output);
        }

        if size > max_size || output.len().saturating_add(size) > max_size {
            return Err(protocol_error("chunked 响应体超过大小限制"));
        }
        if input.len() < size + 2 || &input[size..size + 2] != b"\r\n" {
            return Err(protocol_error("chunked 数据不完整"));
        }
        output.extend_from_slice(&input[..size]);
        input = &input[size + 2..];
    }
}

fn find_crlf(input: &[u8]) -> Option<usize> {
    input.windows(2).position(|window| window == b"\r\n")
}

fn find_double_crlf(input: &[u8]) -> Option<usize> {
    input.windows(4).position(|window| window == b"\r\n\r\n")
}

fn header_value<'a>(headers: &'a [(String, String)], name: &str) -> Option<&'a str> {
    headers
        .iter()
        .find(|(header, _)| header.eq_ignore_ascii_case(name))
        .map(|(_, value)| value.as_str())
}

pub struct HttpRequest {
    pub method: String,
    pub path: String,
    pub headers: Vec<(String, String)>,
    pub body: Vec<u8>,
    connection_header: bool,
}

impl HttpRequest {
    pub fn new(method: &str, path: &str) -> Result<Self, VpnError> {
        if method.is_empty()
            || !method
                .bytes()
                .all(|byte| byte.is_ascii_uppercase() || byte == b'_')
            || !path.starts_with('/')
            || path.starts_with("//")
            || path.chars().any(char::is_control)
        {
            return Err(protocol_error("HTTP 请求方法或路径无效"));
        }
        Ok(Self {
            method: method.to_owned(),
            path: path.to_owned(),
            headers: Vec::new(),
            body: Vec::new(),
            connection_header: true,
        })
    }

    pub(crate) fn omit_connection_header(&mut self) {
        self.connection_header = false;
    }

    pub fn header(&mut self, name: &str, value: &str) -> Result<(), VpnError> {
        if name.is_empty()
            || !name
                .bytes()
                .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
            || value.chars().any(char::is_control)
        {
            return Err(protocol_error("HTTP 请求头无效"));
        }
        self.headers.push((name.to_owned(), value.to_owned()));
        Ok(())
    }

    pub fn to_bytes(&self, host: &str) -> Result<Vec<u8>, VpnError> {
        if host.chars().any(char::is_control) {
            return Err(protocol_error("HTTP Host 无效"));
        }
        let mut output = format!("{} {} HTTP/1.1\r\nHost: {host}\r\n", self.method, self.path);
        for (name, value) in &self.headers {
            output.push_str(&format!("{name}: {value}\r\n"));
        }
        if !self.body.is_empty() || self.method == "POST" {
            output.push_str(&format!("Content-Length: {}\r\n", self.body.len()));
        }
        if self.connection_header
            && !self
                .headers
                .iter()
                .any(|(name, _)| name.eq_ignore_ascii_case("connection"))
        {
            output.push_str("Connection: close\r\n");
        }
        output.push_str("\r\n");
        let mut bytes = output.into_bytes();
        bytes.extend_from_slice(&self.body);
        Ok(bytes)
    }
}

pub(crate) async fn send(
    options: &TlsOptions,
    request: &HttpRequest,
    cancellation: CancellationToken,
) -> Result<HttpResponse, VpnError> {
    let operation = async {
        let mut stream = tls::connect(options).await?;
        let bytes = request.to_bytes(&options.host)?;
        stream.write_all(&bytes).await.map_err(|error| {
            VpnError::new(ErrorCode::NetworkUnavailable, error.to_string(), &[])
        })?;
        read(&mut stream, cancellation.clone())
            .await
            .map(|result| result.response)
    };

    tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(15), operation) => {
            result.map_err(|_| VpnError::new(ErrorCode::NetworkUnavailable, "网关请求超时", &[]))?
        }
        () = cancellation.cancelled() => {
            Err(VpnError::new(ErrorCode::Cancelled, "网关请求已取消", &[]))
        }
    }
}

use crate::{TlsOptions, tls};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

pub(crate) struct HttpReadResult {
    pub response: HttpResponse,
    pub remaining: Vec<u8>,
}

pub(crate) async fn read<S>(
    stream: &mut S,
    cancellation: CancellationToken,
) -> Result<HttpReadResult, VpnError>
where
    S: AsyncReadExt + Unpin,
{
    const MAX_RESPONSE_SIZE: usize = 1024 * 1024;
    let operation = async {
        let mut buffer = Vec::new();
        let mut chunk = [0_u8; 8192];
        loop {
            if let Some(size) = complete_response_size(&buffer)? {
                let response = HttpResponse::parse(&buffer[..size], MAX_RESPONSE_SIZE)?;
                return Ok(HttpReadResult {
                    response,
                    remaining: buffer[size..].to_vec(),
                });
            }

            let count = stream.read(&mut chunk).await.map_err(|error| {
                VpnError::new(ErrorCode::NetworkUnavailable, error.to_string(), &[])
            })?;
            if count == 0 {
                let response = HttpResponse::parse(&buffer, MAX_RESPONSE_SIZE)?;
                return Ok(HttpReadResult {
                    response,
                    remaining: Vec::new(),
                });
            }
            buffer.extend_from_slice(&chunk[..count]);
            if buffer.len() > MAX_RESPONSE_SIZE {
                return Err(protocol_error("HTTP 响应超过大小限制"));
            }
        }
    };

    tokio::select! {
        result = tokio::time::timeout(Duration::from_secs(15), operation) => {
            result.map_err(|_| VpnError::new(ErrorCode::NetworkUnavailable, "读取 HTTP 响应超时", &[]))?
        }
        () = cancellation.cancelled() => {
            Err(VpnError::new(ErrorCode::Cancelled, "读取 HTTP 响应已取消", &[]))
        }
    }
}

fn complete_response_size(input: &[u8]) -> Result<Option<usize>, VpnError> {
    let Some(header_end) = find_double_crlf(input).map(|position| position + 4) else {
        return Ok(None);
    };
    let mut header_buffer = [httparse::EMPTY_HEADER; 64];
    let mut response = httparse::Response::new(&mut header_buffer);
    match response.parse(&input[..header_end]) {
        Ok(httparse::Status::Complete(_)) => {}
        Ok(httparse::Status::Partial) => return Ok(None),
        Err(_) => return Err(protocol_error("HTTP 响应头无效")),
    }

    if let Some(header) = response
        .headers
        .iter()
        .find(|header| header.name.eq_ignore_ascii_case("content-length"))
    {
        let length = std::str::from_utf8(header.value)
            .ok()
            .and_then(|value| value.trim().parse::<usize>().ok())
            .ok_or_else(|| protocol_error("HTTP Content-Length 无效"))?;
        let total = header_end
            .checked_add(length)
            .ok_or_else(|| protocol_error("HTTP 响应长度溢出"))?;
        return Ok((input.len() >= total).then_some(total));
    }

    if response.headers.iter().any(|header| {
        header.name.eq_ignore_ascii_case("transfer-encoding")
            && header.value.eq_ignore_ascii_case(b"chunked")
    }) {
        return chunked_response_size(&input[header_end..])
            .map(|size| size.map(|size| header_end + size));
    }
    Ok(None)
}

fn chunked_response_size(mut input: &[u8]) -> Result<Option<usize>, VpnError> {
    let original = input;
    loop {
        let Some(line_end) = find_crlf(input) else {
            return Ok(None);
        };
        let size_text = std::str::from_utf8(&input[..line_end])
            .map_err(|_| protocol_error("chunked 长度不是文本"))?;
        let size_text = size_text.split(';').next().unwrap_or_default().trim();
        let size =
            usize::from_str_radix(size_text, 16).map_err(|_| protocol_error("chunked 长度无效"))?;
        input = &input[line_end + 2..];
        if size == 0 {
            if input.starts_with(b"\r\n") {
                return Ok(Some(original.len() - input.len() + 2));
            }
            let Some(trailer_end) = find_double_crlf(input) else {
                return Ok(None);
            };
            return Ok(Some(original.len() - input.len() + trailer_end + 4));
        }
        if input.len() < size + 2 {
            return Ok(None);
        }
        if &input[size..size + 2] != b"\r\n" {
            return Err(protocol_error("chunked 数据缺少行结束符"));
        }
        input = &input[size + 2..];
    }
}

fn protocol_error(message: &str) -> VpnError {
    VpnError::new(ErrorCode::ProtocolError, message, &[])
}
