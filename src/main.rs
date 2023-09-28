use std::num::ParseIntError;

fn main() {
    let hex = String::from("1c0111001f010100061a024b53535009181c");
    let buf = String::from("686974207468652062756c6c277320657965");
    println!(
        "{:02X?}",
        fixed_xor(&decode_hex(&hex).unwrap(), &decode_hex(&buf).unwrap())
    );
}

// From https://stackoverflow.com/questions/52987181/how-can-i-convert-a-hex-string-to-a-u8-slice.
fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
}

fn fixed_xor(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    b1.into_iter()
        .zip(b2.into_iter())
        .map(|(u1, u2)| u1 ^ u2)
        .collect()
}
