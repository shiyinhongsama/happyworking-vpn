use base64::{Engine, engine::general_purpose::STANDARD};

const RECOVERED_VERSION_PAYLOAD: [u8; 20] = [
    0x3c, 0x32, 0x5a, 0x1c, 0x78, 0x2e, 0x57, 0x17, 0x53, 0x2e, 0x2b, 0x05, 0x41, 0x52, 0x2b, 0x2e,
    0x58, 0x52, 0x77, 0x8e,
];

pub fn url_encode(input: &str) -> String {
    url_encode_bytes(input.as_bytes())
}

pub fn url_encode_bytes(input: &[u8]) -> String {
    let mut output = String::with_capacity(input.len() * 3);
    for byte in input.iter().copied() {
        if byte.is_ascii_alphanumeric() {
            output.push(char::from(byte));
        } else if byte == b' ' {
            output.push('+');
        } else {
            output.push_str(&format!("%{byte:02X}"));
        }
    }
    output
}

pub fn private_content() -> String {
    let mut content = [0_u8; 22];
    content[0] = 1;
    content[1] = 22;
    content[2..].copy_from_slice(&RECOVERED_VERSION_PAYLOAD);
    STANDARD.encode(content)
}
