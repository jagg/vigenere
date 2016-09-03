use rustc_serialize::hex::{ToHex, FromHex};
use rustc_serialize::base64::{ToBase64, FromBase64, STANDARD};
use std::str;
use std::io::BufWriter;
use std::fs::File;
use std::path::Path;
use std::io::prelude::*;
use std::cmp;
use std::fs::OpenOptions;
use std::fs;


pub struct CipherText(Vec<u8>);

impl CipherText {
    pub fn new(bytes: &[u8]) -> CipherText {
        CipherText(bytes.to_vec())
    }

    pub fn from_hex(hex: &str) -> Result<CipherText, Error> {
        let cipher_bytes: Vec<u8> = try!(hex.from_hex()
            .map_err(|e| Error::Hex(e.to_string())));
        Ok(CipherText(cipher_bytes))
    }

    pub fn to_hex(&self) -> String {
        let &CipherText(ref vec_bytes) = self;
        vec_bytes.to_hex()
    }

    pub fn from_b64(b64: &str) -> Result<CipherText, Error> {
        let cipher_bytes: Vec<u8> = try!(b64.from_base64()
            .map_err(|e| Error::Base64(e.to_string())));
        Ok(CipherText(cipher_bytes))
    }

    pub fn to_b64(&self) -> String {
        let &CipherText(ref vec_bytes) = self;
        vec_bytes.to_base64(STANDARD)
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<CipherText, Error> {
        let path = path.as_ref();
        let mut file = try!(File::open(Path::new(path)).map_err(|e| Error::File(e.to_string())));
        let capacity = file.metadata().ok().map_or(0, |x| x.len());
        let mut buffer = String::with_capacity(capacity as usize);
        try!(file.read_to_string(&mut buffer).map_err(|e| Error::File(e.to_string())));
        CipherText::from_b64(&buffer)
    }

    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let path = path.as_ref();
        let text_b64 = self.to_b64();
        if path.exists() {
            try!(fs::remove_file(path).map_err(|e| Error::File(e.to_string())));
        }

        let mut file = try!(OpenOptions::new()
            .write(true)
            .append(true)
            .create(true)
            .open(path)
            .map_err(|e| Error::File(e.to_string())));

        let mut i = 0;
        let mut j = cmp::min(text_b64.len(), 80);
        while i != j {
            try!(file.write_all(&text_b64[i..j].as_bytes())
                .map_err(|e| Error::File(e.to_string())));


            try!(file.write_all("\n".as_bytes()).map_err(|e| Error::File(e.to_string())));

            i = j;
            j = cmp::min(text_b64.len(), j + 80);
        }
        Ok(())
    }
}
pub struct PlainText(Vec<u8>);

impl PlainText {
    pub fn from_string(string: &str) -> PlainText {
        PlainText(string.as_bytes().to_vec())
    }

    pub fn from_bytes(bytes: &[u8]) -> PlainText {
        PlainText(bytes.to_vec())
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<PlainText, Error> {
        let path = path.as_ref();
        let mut file = try!(File::open(Path::new(path)).map_err(|e| Error::File(e.to_string())));
        let capacity = file.metadata().ok().map_or(0, |x| x.len());
        let mut buffer = String::with_capacity(capacity as usize);
        try!(file.read_to_string(&mut buffer).map_err(|e| Error::File(e.to_string())));
        Ok(PlainText::from_string(&buffer))

    }

    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let path = path.as_ref();
        let &PlainText(ref vec_bytes) = self;
        let file = try!(OpenOptions::new()
            .write(true)
            .truncate(true)
            .create(true)
            .open(path)
            .map_err(|e| Error::File(e.to_string())));

        let mut out_file = BufWriter::new(file);
        try!(out_file.write_all(&vec_bytes).map_err(|e| Error::File(e.to_string())));

        Ok(())
    }

    pub fn to_utf8(&self) -> Result<String, Error> {
        let &PlainText(ref vec_bytes) = self;
        let plain = try!(str::from_utf8(&vec_bytes).map_err(|e| Error::UTF8(e.to_string())));
        Ok(plain.to_string())
    }
}

pub fn encrypt(text: &PlainText, key: &str) -> CipherText {
    let &PlainText(ref bytes) = text;
    let xored: Vec<u8> = repeating_xor(bytes, key.as_bytes());
    CipherText::new(&xored)
}

pub fn decrypt(cipher_text: &CipherText, key: &str) -> Result<PlainText, Error> {
    let &CipherText(ref bytes) = cipher_text;
    let xored: Vec<u8> = repeating_xor(bytes, key.as_bytes());
    Ok(PlainText::from_bytes(&xored))
}

pub fn decrypt_file(input_path: &str, output_path: &str, key: &str) -> Result<(), Error> {
    let cipher = try!(CipherText::from_file(input_path));
    let plain = try!(decrypt(&cipher, key));
    try!(plain.to_file(output_path));
    Ok(())
}

pub fn encrypt_file(input_path: &str, output_path: &str, key: &str) -> Result<(), Error> {
    let plain = try!(PlainText::from_file(input_path));
    let cipher = encrypt(&plain, key);
    try!(cipher.to_file(output_path));
    Ok(())
}

#[derive(Debug)]
pub enum Error {
    Hex(String),
    Base64(String),
    UTF8(String),
    File(String),
}

fn repeating_xor(input: &[u8], key: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    unsafe {
        out.set_len(input.len());
    }
    for (i, in_val) in input.iter().enumerate() {
        out[i] = in_val ^ key[i % key.len()];
    }
    out
}



#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_encrypt_and_decrypt() {
        check_text("This is the plain text\n");
        check_text("123, 456");
        check_text("!£$%^&*@~:");
        check_text("日本語");
    }

    #[test]
    fn test_encrypt_and_decrypt_files() {
        check_text_file("This is the plain text\n");
        check_text_file("123, 456");
        check_text_file("!£$%^&*@~:");
        check_text_file("日本語");
        check_text_file("This is the plain text\nThis is the plain text\nThis is the plain text\n");
    }

    #[test]
    fn test_wrong_key() {
        let text = "This is the plain text";
        let plain_text = PlainText::from_string(text);
        let key: &str = "toy";
        let decoded_text = decrypt(&encrypt(&plain_text, key), "wrong_key").unwrap();
        assert!(text != decoded_text.to_utf8().unwrap());
    }

    fn check_text(text: &str) {
        let plain_text = PlainText::from_string(text);
        let key: &str = "toy";
        let decoded_text = decrypt(&encrypt(&plain_text, key), key).unwrap();
        assert_eq!(text, decoded_text.to_utf8().unwrap());
    }

    fn check_text_file(text: &str) {
        let plain_text = PlainText::from_string(text);
        let key: &str = "toy";
        let plain_path = "./target/test-plain.txt";
        let cipher_path = "./target/test-cipher.txt";
        let decoded_path = "./target/test-decoded.txt";

        plain_text.to_file(plain_path).unwrap();
        encrypt_file(plain_path, cipher_path, key).unwrap();
        decrypt_file(cipher_path, decoded_path, key).unwrap();
        let decoded_text = PlainText::from_file(decoded_path).unwrap();

        assert_eq!(text, decoded_text.to_utf8().unwrap());
    }
}
