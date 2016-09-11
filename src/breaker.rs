use super::cipher;
use super::byte_matrix;
use std::ops::BitAnd;
use std::collections::BinaryHeap;
use std::cmp::Ordering;
use std::f32;

fn calc_size_score(cipher: &[u8], size: i32) -> f32 {

    let b1 = &cipher[0..size as usize];
    let b2 = &cipher[size as usize..2 * size as usize];
    let b3 = &cipher[2 * size as usize..3 * size as usize];
    let b4 = &cipher[3 * size as usize..4 * size as usize];

    let d1 = hamming_dist(b1, b2) as f32;
    let d2 = hamming_dist(b1, b3) as f32;
    let d3 = hamming_dist(b1, b4) as f32;
    let d4 = hamming_dist(b2, b3) as f32;
    let d5 = hamming_dist(b2, b4) as f32;
    let d6 = hamming_dist(b3, b4) as f32;


    ((d1 + d2 + d3 + d4 + d5 + d6) / 6.0) / size as f32

}

#[derive(Copy, Clone, PartialEq, Debug)]
struct KeyScore {
    size: u32,
    score: f32,
}

impl Eq for KeyScore {}

impl Ord for KeyScore {
    fn cmp(&self, other: &KeyScore) -> Ordering {
        other.score.partial_cmp(&self.score).unwrap_or(Ordering::Equal)
    }
}

impl PartialOrd for KeyScore {
    fn partial_cmp(&self, other: &KeyScore) -> Option<Ordering> {
        Some(self.cmp(other))
    }
}

pub fn break_file(input_path: &str, output_path: &str) -> Result<(), cipher::Error> {
    let cipher = try!(cipher::CipherText::from_file(input_path));
    let plain = try!(decode_text(&cipher));
    try!(plain.to_file(output_path));
    Ok(())
}


pub fn decode_text(cipher: &cipher::CipherText) -> Result<cipher::PlainText, cipher::Error> {

    let mut best_score = 0;
    let mut candidate = None;
    let key_size_guesses = guess_key_size(cipher);
    for key_size in key_size_guesses.iter() {
        let plain = break_cipher(cipher, *key_size);
        let score = score(&plain.as_bytes());
        if score > best_score {
            best_score = score;
            candidate = Some(plain);
        }

    }
    match candidate {
        None => Err(cipher::Error::Failure("Couldn't decode text".to_string())),
        Some(plain) => Ok(plain),
    }
}


pub fn guess_key_size(cipher: &cipher::CipherText) -> Vec<u32> {
    let mut heap = BinaryHeap::new();
    let mut best = Vec::new();
    for i in 1..40 {
        let score = calc_size_score(&cipher.as_bytes(), i);
        heap.push(KeyScore {
            size: i as u32,
            score: score,
        });
    }

    let mut count = 0;
    while let Some(v) = heap.pop() {
        if count > 3 {
            break;
        } else {
            best.push(v.size);
            count += 1;
        }
    }
    best
}

pub fn hamming_dist(bytes1: &[u8], bytes2: &[u8]) -> i32 {
    let mut count = 0;
    for (i, val1) in bytes1.iter().enumerate() {
        let diff_bytes = val1 ^ bytes2[i];
        count += count_set_bits(diff_bytes);
    }
    count
}


pub fn count_set_bits(mut byte: u8) -> i32 {
    let mut count = 0;
    while byte != 0 {
        byte = byte.bitand(byte - 1);
        count += 1;
    }
    count
}

pub fn break_cipher(cipher: &cipher::CipherText, key_size: u32) -> cipher::PlainText {
    let matrix = byte_matrix::ByteMatrix::transpose(&cipher.as_bytes(), key_size as usize);
    let matrix = matrix.transform(|vec: &Vec<u8>| {
        let cipher = cipher::CipherText::new(vec);
        let plain = decode_single_key(&cipher);
        plain.as_bytes()
    });
    let decoded = matrix.reassemble();
    let plain = cipher::PlainText::new(&decoded);
    plain
}

pub fn decode_single_key(cipher: &cipher::CipherText) -> cipher::PlainText {
    let mut plain = None;
    let mut best_score = 0;
    for key in 0...255_u8 {
        let candidate = cipher::decrypt_single_key(cipher, key).unwrap();
        let score = score(&candidate.as_bytes());
        if score > best_score {
            best_score = score;
            plain = Some(candidate);
        }
    }
    plain.unwrap()
}

// Measures the number of lowercase characters
fn score(input: &[u8]) -> u32 {
    input.iter().fold(0, |acc, b| {
        if *b >= 97 && *b <= 122 {
            acc + 1
        } else if *b >= 33 && *b <= 64 && acc > 0 {
            acc - 1
        } else {
            acc
        }
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use super::super::cipher;

    #[test]
    fn test_count_bits() {
        assert_eq!(3, count_set_bits(0b0101010));
        assert_eq!(0, count_set_bits(0b0000000));
        assert_eq!(7, count_set_bits(0b1111111));
        assert_eq!(1, count_set_bits(0b0010000));
    }

    #[test]
    fn test_break() {
        check_break_single("This should be a simple test", "b");
        check_break_single("This should be a simple test", "x");
        check_break_single("This should be a simple test", "1");
        check_break_single("En un lugar de la mancha", "9");

        check_break("This should be a simple test with a not too long text",
                    "ace");

    }

    #[test]
    fn test_guess_key() {
        check_guess_key("En un lugar de la Mancha, de cuyo nombre no quiero acordarme, no ha \
                         mucho tiempo que vivía un hidalgo de los de lanza en astillero, adarga \
                         antigua, rocín flaco y galgo corredor. Una olla de algo más vaca que \
                         carnero, salpicón las más noches, duelos y quebrantos los sábados, \
                         lantejas los viernes, algún palomino de añadidura los domingos, \
                         consumían las tres partes de su hacienda. El resto della concluían sayo \
                         de velarte, calzas de velludo para las fiestas, con sus pantuflos de lo \
                         mesmo, y los días de entresemana se honraba con su vellorí de lo más \
                         fino. Tenía en su casa una ama que pasaba de los cuarenta, y una \
                         sobrina que no llegaba a los veinte, y un mozo de campo y plaza, que \
                         así ensillaba el rocín como tomaba la podadera. Frisaba la edad de \
                         nuestro hidalgo con los cincuenta años; era de complexión recia, seco \
                         de carnes, enjuto de rostro, gran madrugador y amigo de la caza. \
                         Quieren decir que tenía el sobrenombre de Quijada, o Quesada, que en \
                         esto hay alguna diferencia en los autores que deste caso escriben; \
                         aunque, por conjeturas verosímiles, se deja entender que se llamaba \
                         Quejana. Pero esto importa poco a nuestro cuento; basta que en la \
                         narración dél no se salga un punto de la verdad.",
                        "caracol");

    }

    fn check_guess_key(text: &str, key: &str) {
        let plain = cipher::PlainText::from_string(text);
        let cipher = cipher::encrypt(&plain, key);
        assert!(guess_key_size(&cipher).contains(&(key.len() as u32)));
    }

    fn check_break(text: &str, key: &str) {
        let plain = cipher::PlainText::from_string(text);
        let cipher = cipher::encrypt(&plain, key);
        let decoded = break_cipher(&cipher, key.len() as u32);
        assert_eq!(text, decoded.to_utf8().unwrap());
    }

    fn check_break_single(text: &str, key: &str) {
        let plain = cipher::PlainText::from_string(text);
        let cipher = cipher::encrypt(&plain, key);
        let decoded = decode_single_key(&cipher);
        assert_eq!(text, decoded.to_utf8().unwrap());
    }





    #[test]
    fn test_hamming_dist() {
        assert_eq!(37,
                   hamming_dist("this is a test".as_bytes(), "wokka wokka!!!".as_bytes()));
    }
}
