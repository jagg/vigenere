extern crate vigenere;
extern crate getopts;

use vigenere::cypher::{decrypt_file, encrypt_file};
use getopts::*;
use std::env;

fn main() {
    let args: Vec<String> = env::args().collect();
    let mut opts = Options::new();

    opts.optopt("i", "", "Input file", "INPUT_FILE");
    opts.optopt("o", "", "Output file", "OUTPUT_FILE");
    opts.optopt("k", "", "Key", "KEY_STRING");
    opts.optflag("d", "", "Decrypt");

    let matches = opts.parse(&args[1..]).unwrap();
    let input = matches.opt_str("i").unwrap();
    let output = matches.opt_str("o").unwrap();
    let key = matches.opt_str("k").unwrap();
    let decrypt = matches.opt_present("d");

    if decrypt {
        match decrypt_file(&input, &output, &key) {
            Ok(_) => println!("Done!"),
            Err(err) => println!("Error found: {:?}", err),
        }
    } else {
        match encrypt_file(&input, &output, &key) {
            Ok(_) => println!("Done!"),
            Err(err) => println!("Error found: {:?}", err),
        }

    }

}
