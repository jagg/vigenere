use rustc_serialize::hex::{ToHex, FromHex, FromHexError};
use rustc_serialize::base64::{FromBase64Error, ToBase64, FromBase64, STANDARD};
use std::str;
use std::io;
use std::io::BufWriter;
use std::fs::File;
use std::path::Path;
use std::io::prelude::*;
use std::cmp;
use std::fs::OpenOptions;
use std::fs;

enum WriteMethod {
    Truncate,
    Append,
}

pub struct CipherText(Vec<u8>);

impl CipherText {
    pub fn new(bytes: &[u8]) -> CipherText {
        CipherText(bytes.to_vec())
    }

    pub fn from_hex(hex: &str) -> Result<CipherText, Error> {
        let cipher_bytes: Vec<u8> = try!(hex.from_hex());
        Ok(CipherText(cipher_bytes))
    }

    pub fn to_hex(&self) -> String {
        let ref vec_bytes = self.0;
        vec_bytes.to_hex()
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    pub fn from_b64<S: AsRef<str>>(b64: S) -> Result<CipherText, Error> {
        let cipher_bytes: Vec<u8> = try!(b64.as_ref().from_base64());
        Ok(CipherText(cipher_bytes))
    }

    pub fn to_b64(&self) -> String {
        let ref vec_bytes = self.0;
        vec_bytes.to_base64(STANDARD)
    }

    pub fn from_file<P: AsRef<Path>>(path: P) -> Result<CipherText, Error> {
        buffer_file(path.as_ref()).and_then(CipherText::from_b64)
    }

    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let text_b64 = self.to_b64();
        let mut file = try!(create_file(path.as_ref(), WriteMethod::Append));

        let mut i = 0;
        let mut j = cmp::min(text_b64.len(), 80);
        while i != j {
            try!(file.write_all(&text_b64[i..j].as_bytes()));
            try!(file.write_all("\n".as_bytes()));

            i = j;
            j = cmp::min(text_b64.len(), j + 80);
        }
        Ok(())
    }
}
pub struct PlainText(Vec<u8>);

impl PlainText {
    pub fn new(bytes: &[u8]) -> PlainText {
        PlainText(bytes.to_vec())
    }

    pub fn from_string<S: AsRef<str>>(string: S) -> PlainText {
        PlainText(string.as_ref().as_bytes().to_vec())
    }

    pub fn from_bytes(bytes: &[u8]) -> PlainText {
        PlainText(bytes.to_vec())
    }

    pub fn as_bytes(&self) -> Vec<u8> {
        self.0.clone()
    }

    fn from_file<P: AsRef<Path>>(path: P) -> Result<PlainText, Error> {
        buffer_file(path.as_ref()).map(PlainText::from_string)
    }

    pub fn to_file<P: AsRef<Path>>(&self, path: P) -> Result<(), Error> {
        let ref vec_bytes = self.0;
        let file = try!(create_file(path.as_ref(), WriteMethod::Truncate));
        let mut out_file = BufWriter::new(file);
        try!(out_file.write_all(&vec_bytes));
        Ok(())
    }

    pub fn to_utf8(&self) -> Result<String, Error> {
        let ref vec_bytes = self.0;
        let plain = try!(str::from_utf8(&vec_bytes));
        Ok(plain.to_string())
    }
}

fn buffer_file(path: &Path) -> Result<String, Error> {
    let mut file = try!(File::open(Path::new(path)));
    let capacity = file.metadata().ok().map_or(0, |x| x.len());
    let mut buffer = String::with_capacity(capacity as usize);
    try!(file.read_to_string(&mut buffer));
    Ok(buffer)
}

fn create_file(path: &Path, method: WriteMethod) -> Result<File, Error> {
    if path.exists() {
        try!(fs::remove_file(path));
    }

    match method {
        WriteMethod::Append => {
            OpenOptions::new()
                .write(true)
                .append(true)
                .create(true)
                .open(path)
                .map_err(|e| Error::from(e))
        }
        WriteMethod::Truncate => {
            OpenOptions::new()
                .write(true)
                .truncate(true)
                .create(true)
                .open(path)
                .map_err(|e| Error::from(e))
        }
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

pub fn decrypt_single_key(cipher_text: &CipherText, key: u8) -> Result<PlainText, Error> {
    let &CipherText(ref bytes) = cipher_text;
    let xored: Vec<u8> = repeating_xor(bytes, &vec![key]);
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

impl From<FromBase64Error> for Error {
    fn from(err: FromBase64Error) -> Error {
        Error::Base64(err.to_string())
    }
}

impl From<FromHexError> for Error {
    fn from(err: FromHexError) -> Error {
        Error::Hex(err.to_string())
    }
}

impl From<str::Utf8Error> for Error {
    fn from(err: str::Utf8Error) -> Error {
        Error::UTF8(err.to_string())
    }
}

impl From<io::Error> for Error {
    fn from(err: io::Error) -> Error {
        Error::File(err.to_string())
    }
}

fn repeating_xor(input: &[u8], key: &[u8]) -> Vec<u8> {
    let mut out: Vec<u8> = Vec::with_capacity(input.len());
    for (i, in_val) in input.iter().enumerate() {
        out.push(in_val ^ key[i % key.len()]);
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
        check_text_file("dsklfshdfsfsdfsdfsdfsdfsgfssssssssssssssssssssssfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    }

    #[test]
    fn test_file_storage() {
        check_to_from_file("This is the plain text\n");
        check_to_from_file("123, 456");
        check_to_from_file("!£$%^&*@~:");
        check_to_from_file("日本語");
        check_to_from_file("This is the plain text\nThis is the plain text\nThis is the plain \
                            text\n");
        check_to_from_file("dsklfshdfsfsdfsdfsdfsdfsgfssssssssssssssssssssssfffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    }

    #[test]
    fn test_wrong_key() {
        let text = "This is the plain text";
        let plain_text = PlainText::from_string(text);
        let key: &str = "toy";
        let decoded_text = decrypt(&encrypt(&plain_text, key), "wrong_key").unwrap();
        assert!(text != decoded_text.to_utf8().unwrap());
    }

    fn check_to_from_file(text: &str) {
        let plain_text = PlainText::from_string(text);
        let key: &str = "toy";
        let cipher_text = encrypt(&plain_text, key);
        let path = "./target/debug/test.txt";

        plain_text.to_file(&path).unwrap();
        let rec_plain = PlainText::from_file(&path).unwrap();
        assert_eq!(plain_text.to_utf8().unwrap(), rec_plain.to_utf8().unwrap());

        cipher_text.to_file(&path).unwrap();
        let rec_cipher = CipherText::from_file(&path).unwrap();
        assert_eq!(cipher_text.to_b64(), rec_cipher.to_b64());

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
