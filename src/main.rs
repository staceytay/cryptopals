use base64::{engine::general_purpose, Engine as _};
use openssl::symm::{decrypt, Cipher};

const FILE: &'static str = include_str!("../7.txt");
const KEY: &'static str = "YELLOW SUBMARINE";

fn main() {
    let bytes = general_purpose::STANDARD
        .decode(FILE.replace('\n', ""))
        .unwrap();
    let cipher = Cipher::aes_128_ecb();
    let message = decrypt(cipher, KEY.as_bytes(), None, &bytes).unwrap();
    println!("{:-^64}", "MESSAGE");
    println!("{}", String::from_utf8(message).unwrap());
}
