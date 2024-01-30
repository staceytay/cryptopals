# cryptopals

An ongoing attempt at solving the [cryptopals crypto challenges](https://cryptopals.com) in Rust.

## Set 1: Basics

1. [Convert hex to base64](https://cryptopals.com/sets/1/challenges/1) ([solution](https://github.com/staceytay/cryptopals/blob/2ccfb1dd805339b913d96d551de1c66e2620ce19/src/main.rs))
2. [Fixed XOR](https://cryptopals.com/sets/1/challenges/2) ([solution](https://github.com/staceytay/cryptopals/blob/97b99cb8d91d5e81dc7b03e788ea648cbc3bed3c/src/main.rs))
3. [Single-byte XOR cipher](https://cryptopals.com/sets/1/challenges/3) ([solution](https://github.com/staceytay/cryptopals/blob/360bf6b8f5f4b7232c059ad4249a689efa87fdc5/src/main.rs))
4. [Detect single-character XOR](https://cryptopals.com/sets/1/challenges/4) ([solution](https://github.com/staceytay/cryptopals/blob/75476c8173fc14df4acf22b798ec9ad5b75e4e0f/src/main.rs))
5. [Implement repeating-key XOR](https://cryptopals.com/sets/1/challenges/5) ([solution](https://github.com/staceytay/cryptopals/blob/534241729a8b023c6ec60c4622807807e8c016e8/src/main.rs))
6. [Break repeating-key XOR](https://cryptopals.com/sets/1/challenges/6) ([solution](https://github.com/staceytay/cryptopals/blob/f19e329293b01fbe792c37e04d5d8f293f3c59bd/src/main.rs))
7. [AES in ECB mode](https://cryptopals.com/sets/1/challenges/7) ([solution](https://github.com/staceytay/cryptopals/blob/2805367fcd4f3d1be418a7be75562156dd3ad58f/src/main.rs))
8. [Detect AES in ECB mode](https://cryptopals.com/sets/1/challenges/8) ([solution](https://github.com/staceytay/cryptopals/blob/3213f31e624ec3a2661340ccb35c458555112501/src/main.rs))

## Set 2: Block crypto

9. [Implement PKCS#7 padding](https://cryptopals.com/sets/2/challenges/9) ([solution](https://github.com/staceytay/cryptopals/blob/09c8e227d693b5c51d2ddce2a8ee6b9645feef3e/src/main.rs))
10. [Implement CBC mode](https://cryptopals.com/sets/2/challenges/10) ([solution](https://github.com/staceytay/cryptopals/blob/8a29ff8ecfcf2145952cc727083fb5f66ebd4f45/src/main.rs))
11. [An ECB/CBC detection oracle](https://cryptopals.com/sets/2/challenges/11) ([solution](https://github.com/staceytay/cryptopals/blob/d0beb87753a020575c0f41753812e5199d328657/src/main.rs))
12. [Byte-at-a-time ECB decryption (Simple)](https://cryptopals.com/sets/2/challenges/12) ([solution](https://github.com/staceytay/cryptopals/blob/9364b4326c3839fb003e13d785053c7f45267a/src/main.rs))
13. [ECB cut-and-paste](https://cryptopals.com/sets/2/challenges/13) ([notes](https://github.com/staceytay/cryptopals/tree/main#set-2-challenge-13)) ([solution](https://github.com/staceytay/cryptopals/blob/7669e1e3f0dce043f48d04afec1edf91cbeb62cb/src/main.rs))
14. [Byte-at-a-time ECB decryption (Harder)](https://cryptopals.com/sets/2/challenges/14) ([notes](https://github.com/staceytay/cryptopals#set-2-challenge-14)) ([solution](https://github.com/staceytay/cryptopals/blob/7ede4f76e7a87d97e83b3edf83befef4f14f8223/src/main.rs))
15. [PKCS#7 padding validation](https://cryptopals.com/sets/2/challenges/15) ([solution](https://github.com/staceytay/cryptopals/blob/b1c2572e4b60c7d847a860fcab13e0a549dedec3/src/main.rs))
16. [CBC bitflipping attacks](https://cryptopals.com/sets/2/challenges/16)

## Notes (spoiler alert!)

### Set 2 Challenge 13
This attack relies on crafting an input such that we'd be able to get the
desired ciphertext containing the text "role=admin". (In retrospect, the title
of the problem is quite a giveaway.)

The first email validation function I wrote only allowed alphanumeric characters
and the `@` and `.` characters. Based on a closer reading of the problem
statement, I then changed it to only remove `&` and `=`, allowing for injecting
the padding characters. Since this didn't seem too realistic for a real world
email validation function, I was unsure if this was the best approach. But after
discussing it with some other Recurse folks working on cryptopals, it seems to
be the only approach we can think of (so far!).

One cool thing that I did learn from this is that emails can contain some special
characters! From Wikipedia's [page](https://en.wikipedia.org/wiki/Email_address)
on email addresses:
> If quoted, it may contain Space, Horizontal Tab (HT), any ASCII graphic except
> Backslash and Quote and a quoted-pair consisting of a Backslash followed by
> HT, Space or any ASCII graphic; it may also be split between lines anywhere
> that HT or Space appears. 

So I know that at least the ascii code 9 (HT) is allowed, but unfortunately the
padding code that I'd need for this attack is 11 and I can't find anything
definitive on its validity from the wiki page or from [RFC5322: Internet Message
Format](https://datatracker.ietf.org/doc/html/rfc5322#section-3.2.3).

``` rust
let ciphertext = [
    // The chosen input here would produce a ciphertext with three blocks
    // and the last block would be
    // "user\u{c}\u{c}\u{c}\u{c}\u{c}\u{c}\u{c}\u{c}\u{c}\u{c}\u{c}\u{c}".
    // We take the first two blocks of this ciphertext.
    &ecb_encrypt(profile_for("admin@bar.com").as_bytes(), &key)[..32],
    // The chosen input here would produce a ciphertext with the second
    // block being
    // "admin\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}". We
    // append this block to the previous two blocks above to form our
    // desired role=admin profile.
    &ecb_encrypt(
        profile_for(
            "1234567890admin\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}\u{b}",
        )
        .as_bytes(),
        &key,
    )[16..32],
]
.concat();

assert_eq!(
    "email=admin@bar.com&uid=10&role=admin",
    String::from_utf8(ecb_decrypt(&ciphertext, &key)).unwrap()
);
```

### Set 2 Challenge 14
> Now generate a random count of random bytes and prepend this string to every
> plaintext.

At first I misread and mistakenly thought that the random prefix changes with
each call to the oracle function. That would have made the solution much harder,
although still possible (I think). Solving for the case when the random prefix
is fixed makes the problem much more tractable. Solution sketch:
1. Find the length of the random prefix.
2. Repeat the steps in challenge 12 but ignoring the first *n* blocks that
   corresponds to the random prefix when calling the oracle function.
