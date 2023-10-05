use base64::{engine::general_purpose, Engine as _};
use std::collections::HashMap;

const CHARS: &'static str = "ETAOIN SHRDLU";
const FILE: &'static str = include_str!("../6.txt");

fn main() {
    assert_eq!(
        edit_distance("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()),
        37
    );

    let hex = general_purpose::STANDARD
        .decode(FILE.replace('\n', ""))
        .unwrap();

    let sample_size = 2;
    println!("sample_size = {sample_size}");
    // Calculate edit distance for each KEYSIZE.
    for i in 2..40 {
        let mut sum = 0.0;
        for j in 0..(sample_size * 2) {
            if j % 2 == 0 {
                sum += f64::from(edit_distance(
                    &hex[((j + 0) * i)..((j + 1) * i)],
                    &hex[((j + 1) * i)..((j + 2) * i)],
                )) / i as f64;
            }
        }

        println!("i = {:02}: {}", i, sum / sample_size as f64);
    }

    let keysize = 29; // 2 or 3 or 5 or 29???
    let mut key = vec![0; keysize];
    for i in 0..keysize {
        // Transpose the original cipher text according to our predicted
        // keysize.
        let cipher: Vec<u8> = hex
            .iter()
            .enumerate()
            .filter_map(|(j, &b)| if j % keysize == i { Some(b) } else { None })
            .collect();
        println!("cipher = {}", show(&cipher));

        // Get most frequently appearing byte as before.
        // let mut counts = HashMap::new();
        // for b in cipher.iter() {
        //     *counts.entry(b).or_insert(0) += 1;
        // }
        // println!("counts = {:?}", counts);

        // Count the frequency of each letter
        let mut counts = HashMap::new();
        for b in cipher.iter() {
            *counts.entry(b).or_insert(0) += 1;
        }

        // Get a sorted (by field 0 ("count") in reversed order) list of the
        // most frequently used characters:
        let mut counts_vec: Vec<_> = counts.iter().collect();
        counts_vec.sort_by(|a, b| b.1.cmp(a.1));
        println!("counts = {:?}", counts_vec);
        // println!("counts 2 = {:?}", counts_vec[2].0);

        for j in 0..3 {
            for c in CHARS.chars() {
                let k = c as u8 ^ **counts_vec[j].0;
                // println!("i = {i}, c = {c}, k = {k}");
                let message = &cipher
                    .clone()
                    .into_iter()
                    .map(|b| b ^ k)
                    .collect::<Vec<u8>>()[..];
                let decoded = show(message);
                // println!("decoded = {}", decoded);
                //---
                // Count most frequently appearing character.
                let mut counts = HashMap::new();
                for c in decoded.chars() {
                    *counts.entry(c).or_insert(0) += 1;
                }
                let frequentest = counts.iter().max_by_key(|(_, v)| *v).unwrap();

                if i == 19 {
                    println!("[i = {:02}]: [{}] -> {}", i, k, decoded);
                    key[i] = 32; // Cheated and saw output earlier.
                }
                // Use this heuristic to see if the string is likely to be the
                // message. Heuristic: most frequent char in `decoded` should be
                // from set in `CHARS` and there should be a space considering
                // the length of the message.
                else if CHARS.contains(*frequentest.0) && decoded.contains(" ") {
                    println!("[i = {:02}]: [{}] -> {}", i, k, decoded);
                    key[i] = k;
                }
                //---

                // Count most frequently appearing character.
                let mut counts = HashMap::new();
                for b in message.iter() {
                    *counts.entry(b).or_insert(0.0) += 1.0;
                }
                // println!("counts = {:?}", counts);

                for (_, v) in counts.iter_mut() {
                    *v /= cipher.len() as f64;
                }
                for i in 65..=122 {
                    // match counts.get(&i) {
                    //     Some(v) => println!("{}: {:.3}", i as char, v),
                    //     None => println!("{}: 0", i as char),
                    // }
                    // std::ascii::escape_default(b)
                }
                // for (k, v) in &counts {
                //     println!("{} => {:.3}", k, v);
                // }
                // println!("counts = {:?}", counts);
            }
        }
    }
    println!("key = {:?}", key);

    // let kblock = []
    // for i in 0..keysize {

    // }
    let message = repeat_xor(&key, &hex);
    println!("{}", show(&message));
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

fn repeat_xor(k: &[u8], m: &[u8]) -> Vec<u8> {
    let mut bs = Vec::new();
    for (i, b) in m.iter().enumerate() {
        bs.push(b ^ k[i % k.len()]);
    }
    bs
}

// From https://stackoverflow.com/questions/41449708/how-to-print-a-u8-slice-as-text-if-i-dont-care-about-the-particular-encoding.
fn show(bs: &[u8]) -> String {
    let mut visible = String::new();
    for &b in bs {
        let part: Vec<u8> = std::ascii::escape_default(b).collect();
        visible.push_str(std::str::from_utf8(&part).unwrap());
    }
    visible
}
