use aes::cipher::{
    generic_array::{typenum::U16, GenericArray},
    BlockEncrypt, KeyInit,
};
use aes::Aes128;
use base64::{engine::general_purpose, Engine as _};

const BLOCK_SIZE: usize = 16;

fn main() {
    let hex =
        String::from("L77na/nrFsKvynd6HzOoG7GHTLXsTVu9qvY/2syLXzhPweyyMTJULu/6/kXX0KSvoOLSFQ==");
    let ciphertext = general_purpose::STANDARD.decode(hex).unwrap();
    let plaintext = ctr(0, b"YELLOW SUBMARINE", &ciphertext);

    assert_eq!(&ciphertext, &ctr(0, b"YELLOW SUBMARINE", &plaintext));

    println!("{:-^64}", "PLAINTEXT");
    println!("{}", String::from_utf8(plaintext).unwrap());
    println!("{:-^64}", "END");
}

fn ctr(nonce: u64, key: &[u8], bytes: &[u8]) -> Vec<u8> {
    let key = GenericArray::<u8, U16>::clone_from_slice(key);
    let cipher = Aes128::new(&key);

    let mut count = 0u64;
    let mut input_block = [nonce.to_le_bytes(), count.to_le_bytes()].concat();
    let mut message = Vec::new();

    let mut iter = bytes.chunks(BLOCK_SIZE);
    while let Some(chunk) = iter.next() {
        let mut block = GenericArray::<u8, U16>::clone_from_slice(&input_block);
        cipher.encrypt_block(&mut block);

        message.extend(fixed_xor(&block, &chunk));

        count += 1;
        input_block = [nonce.to_le_bytes(), count.to_le_bytes()].concat();
    }
    message
}

fn fixed_xor(b1: &[u8], b2: &[u8]) -> Vec<u8> {
    b1.into_iter()
        .zip(b2.into_iter())
        .map(|(u1, u2)| u1 ^ u2)
        .collect()
}
