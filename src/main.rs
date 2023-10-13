use base64::{engine::general_purpose, Engine as _};
use openssl::symm::{decrypt, Cipher};

const FILE_7: &'static str = include_str!("../7.txt");
const FILE_8: &'static str = include_str!("../8.txt");

fn main() {
    let song = general_purpose::STANDARD
        .decode(FILE_7.replace("\n", ""))
        .unwrap();

    let mut min: f64 = 100.0;
    for (linum, line) in FILE_8.split("\n").enumerate() {
        let bytes = general_purpose::STANDARD.decode(line).unwrap();

        let block_size = 16;
        let num_blocks = bytes.len() / block_size;
        let mut sum = 0;
        for i in 0..num_blocks {
            for j in 0..(song.len() / block_size) {
                sum += edit_distance(
                    &bytes[((i + 0) * block_size)..((i + 1) * block_size)],
                    &song[((j + 0) * block_size)..((j + 1) * block_size)],
                );
            }
        }

        let distance = sum as f64 / ((num_blocks * (song.len() / block_size)) as f64);
        println!("LINE = {:02}: {:.3}, {sum}", linum, distance);
        min = min.min(distance);
        // // println!("Edit distance (avg) comparing {comparisons} blocks");
        // let mut sum = 0.0;

        // for j in 0..comparisons {
        //     sum += f64::from(edit_distance(
        //         &bytes[((j + 0) * block_size)..((j + 1) * block_size)],
        //         &bytes[((j + 1) * block_size)..((j + 2) * block_size)],
        //     )) / block_size as f64;
        // }
        // let distance = sum / comparisons as f64;

        // println!("KEYSIZE = {:02}: {:.3}", block_size, distance);
        // println!("");

        // let cipher = Cipher::aes_128_ecb();
        // if let Ok(message) = decrypt(cipher, KEY.as_bytes(), None, &bytes) {
        //     println!("message: {}", String::from_utf8(message).unwrap());
        // }
    }
    println!("MIN: {}", min);
}

fn edit_distance(b1: &[u8], b2: &[u8]) -> u32 {
    let mut distance = 0;
    for i in 0..b1.len() {
        for j in 0..u8::BITS {
            if (b1[i] >> j ^ b2[i] >> j) & 1 as u8 == 0b________1 {
                distance += 1;
            }
        }
    }
    distance
}
