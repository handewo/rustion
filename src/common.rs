use rand::{prelude::*, seq::SliceRandom};
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
