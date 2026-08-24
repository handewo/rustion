use lazy_static::lazy_static;
use rand::{prelude::*, seq::SliceRandom};
use regex::Regex;

lazy_static! {
    pub static ref EMAIL_REGEX: Regex =
        Regex::new(r"^\w+([-+.']\w+)*@\w+([-.]\w+)*\.\w+([-.]\w+)*$").unwrap();
}

pub fn gen_password(len: usize) -> String {
    let upper = b'A'..=b'Z';
    let lower = b'a'..=b'z';
    let digit = b'0'..=b'9';
    let symbol = b"!@#$%^&*-_+=<>?";

    // ensure at least one char from every required set
    let mut rng = rand::rng();
    let mut pwd = Vec::with_capacity(len);

    pwd.push(*upper.clone().collect::<Vec<_>>().choose(&mut rng).unwrap() as char);
    pwd.push(*lower.clone().collect::<Vec<_>>().choose(&mut rng).unwrap() as char);
    pwd.push(*digit.clone().collect::<Vec<_>>().choose(&mut rng).unwrap() as char);
    pwd.push(*symbol.choose(&mut rng).unwrap() as char);

    // fill the rest with random picks from the combined pool
    let pool: Vec<u8> = upper
        .chain(lower)
        .chain(digit)
        .chain(symbol.iter().copied())
        .collect();

    for _ in 4..len {
        pwd.push(*pool.choose(&mut rng).unwrap() as char);
    }

    // shuffle to avoid fixed positions for the mandatory chars
    pwd.shuffle(&mut rng);
    pwd.into_iter().collect()
}

const HEAD_LEN: usize = 8;
const TAIL_LEN: usize = 16;

pub fn shorten_ssh_pubkey(input: &str) -> String {
    let mut it = input.split_whitespace();
    let key_type = it.next().unwrap_or_default();
    let key_data = it.next().unwrap_or_default();
    let comment = it.next();

    if key_data.len() <= HEAD_LEN + TAIL_LEN {
        return input.to_string();
    }

    let head = &key_data[..HEAD_LEN];
    let tail = &key_data[key_data.len() - TAIL_LEN..];

    match comment {
        Some(c) => format!("{key_type} {head}...{tail} {c}"),
        None => format!("{key_type} {head}...{tail}"),
    }
}
