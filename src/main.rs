use base64::{engine::general_purpose, Engine as _};
use std::num::ParseIntError;

fn main() {
    let hex = String::from("49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d");
    println!("{}", hex_to_base64(&hex));
}

// From https://stackoverflow.com/questions/52987181/how-can-i-convert-a-hex-string-to-a-u8-slice.
fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

fn hex_to_base64(hex: &str) -> String {
    general_purpose::STANDARD.encode(decode_hex(&hex).unwrap())
}
