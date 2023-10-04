use std::fmt::Write;

fn main() {
    let l1 = "Burning 'em, if you ain't quick and nimble
I go crazy when I hear a cymbal";
    let c1 = format!(
        "{}{}",
        "0b3637272a2b2e63622c2e69692a23693a2a3c6324202d623d63343c2a26226324272765272",
        "a282b2f20430a652e2c652a3124333a653e2b2027630c692b20283165286326302e27282f"
    );

    let k: &'static str = "ICE";

    assert_eq!(encode_hex(&repeat_xor(k, &l1)), c1);
}

fn repeat_xor(k: &str, m: &str) -> Vec<u8> {
    let mut bs = Vec::new();
    for (i, b) in m.as_bytes().into_iter().enumerate() {
        bs.push(b ^ k.as_bytes()[i % k.len()]);
    }
    bs
}

// From https://stackoverflow.com/questions/52987181/how-can-i-convert-a-hex-string-to-a-u8-slice.
pub fn encode_hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for &b in bytes {
        write!(&mut s, "{:02x}", b).unwrap();
    }
    s
}
