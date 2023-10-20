use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockDecrypt, KeyInit,
};
use aes::Aes128;
use base64::{engine::general_purpose, Engine as _};

const FILE: &'static str = include_str!("../7.txt");
const KEY: &'static [u8; 16] = b"YELLOW SUBMARINE";

fn main() {
    let bytes = general_purpose::STANDARD
        .decode(FILE.replace('\n', ""))
        .unwrap();

    let key = GenericArray::from(*KEY);
    let cipher = Aes128::new(&key);

    let block_size = 16;
    let mut message = Vec::new();
    for i in 0..(bytes.len() / block_size) {
        let mut block = GenericArray::<u8, U16>::clone_from_slice(
            &bytes[(i * block_size)..((i + 1) * block_size)],
        );
        cipher.decrypt_block(&mut block);
        message.extend(block);
    }

    println!("{:-^64}", "MESSAGE");
    println!("{}", String::from_utf8(message).unwrap());
}
