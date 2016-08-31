# vigenere
Encrypt/Decrypt files using the Vigenere cipher

## Usage
The program takes parameters in the command line, it requires an input file, plain text or
encrypted, depending on the operation, an output file where the results will be stored, a
string key and optionally a flag `-d`, to decrypt instead of encrypt.

```
vigenere -i ./input.txt -o ./output.txt -k KEY -d
```
