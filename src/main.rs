use std::num::ParseIntError;

const FILE_8: &'static str = include_str!("../8.txt");

fn main() {
    let mut results = Vec::new();
    for (linum, line) in FILE_8.split("\n").enumerate() {
        let bytes = decode_hex(line).unwrap();

        // Compare each block in the ciphertext with each other and compute
        // their average edit distance.
        let block_size = 16;
        let num_blocks = bytes.len() / block_size;
        let mut sum = 0;
        for i in 0..num_blocks {
            for j in (i + 1)..num_blocks {
                sum += edit_distance(
                    &bytes[((i + 0) * block_size)..((i + 1) * block_size)],
                    &bytes[((j + 0) * block_size)..((j + 1) * block_size)],
                );
            }
        }

        let distance = sum as f64 / ((120) as f64);
        results.push((linum, distance));
    }
    results.sort_by(|a, b| b.1.partial_cmp(&a.1).unwrap());

    for (linum, distance) in results {
        println!("LINE = {:03}: {:.3}", linum, distance);
    }
}

// From https://stackoverflow.com/questions/52987181/how-can-i-convert-a-hex-string-to-a-u8-slice.
fn decode_hex(s: &str) -> Result<Vec<u8>, ParseIntError> {
    (0..s.len())
        .step_by(2)
        .map(|i| u8::from_str_radix(&s[i..i + 2], 16))
        .collect()
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
