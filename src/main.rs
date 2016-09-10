extern crate vigenere;
extern crate getopts;

use vigenere::cipher::{decrypt_file, encrypt_file};
use vigenere::breaker::break_file;
use getopts::*;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut opts = Options::new();

    opts.optopt("i", "", "Input file", "INPUT_FILE");
    opts.optopt("o", "", "Output file", "OUTPUT_FILE");
    opts.optopt("k", "", "Key", "KEY_STRING");
    opts.optflag("d", "", "Decrypt");
    opts.optflag("b", "", "Break cipher without key");

    let matches = opts.parse(&args[1..]).unwrap();
    let input = matches.opt_str("i").unwrap();
    let output = matches.opt_str("o").unwrap();
    let decrypt = matches.opt_present("d");
    let break_cipher = matches.opt_present("b");

    if break_cipher {
        match break_file(&input, &output) {
            Ok(_) => println!("Done!"),
            Err(err) => println!("Error found: {:?}", err),
        }

    } else if decrypt {
        let key = matches.opt_str("k").unwrap();
        match decrypt_file(&input, &output, &key) {
            Ok(_) => println!("Done!"),
            Err(err) => println!("Error found: {:?}", err),
        }
    } else {
        let key = matches.opt_str("k").unwrap();
        match encrypt_file(&input, &output, &key) {
            Ok(_) => println!("Done!"),
            Err(err) => println!("Error found: {:?}", err),
        }

    }

}
