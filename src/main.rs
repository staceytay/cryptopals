fn main() {
    assert!(validate_pkcs7pad(&pkcs7pad(b"ICE ICE BABY", 16)).is_ok());
    assert!(validate_pkcs7pad(b"ICE ICE BABY\x04\x04\x04\x04").is_ok());
    assert!(validate_pkcs7pad(b"ICE ICE BABY\x05\x05\x05\x05").is_err());
    assert!(validate_pkcs7pad(b"ICE ICE BABY\x01\x02\x03\x04").is_err());
}

fn validate_pkcs7pad(plaintext: &[u8]) -> Result<(), &'static str> {
    let padding_length = *plaintext.last().unwrap();
    for i in 1..=padding_length {
        if plaintext[plaintext.len() - i as usize] != padding_length {
            return Err("invalid padding character");
        }
    }
    Ok(())
}

fn pkcs7pad(block: &[u8], length: usize) -> Vec<u8> {
    let mut padded = Vec::from(block);
    padded.resize(length, (length - block.len()) as u8);
    padded
}
