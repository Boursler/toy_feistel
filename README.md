## A Feistel cipher called PSU Crypt

This is a toy cipher implemented by a student, the code is not to be used for
real-life cryptographic needs. I provide no warranty that any security based on
this program would be secure.

PSU Crypt is based on Skipjack by the NSA and Twofish by Bruce Schneier, John
Kelsey, Doug Whiting, David Wagner and Chris Hall. PSU Crypt was designed and
offered as a course project in CS585 Cryptography by Dr. Sarah Mocas at Portland
State University. Here I reproduce my project, with some changes, with her permission.

PSU Crypt is a Feistel cipher, a type of symmetric block cipher in which data to
be encrypted is repeatedly run through *rounds* in which a function is run on
half the data and the output is XORed against the other half.

Inputs are an 80-bit hexadecimal key provided in a key file called key.txt and a
hexadecimal message that the program breaks into 64-bit blocks and encrypts,
then decrypts that the main driver checks that the two match. The encrypted text
is written to an output file.

### Files:

sample_key.txt: an example input key
plaintext.txt: an example message to encrypt
ciphertext.txt: Output for the given samples
psu_crypt.cpp: the source code.

### Build and Run

- Build using ``` g++ -o psu_crypt psu_crypt.cpp ```
- Run with  ``` ./psu_crypt keyfile.txt plaintext.txt ```

### Output

Program outputs to the command line and also to a file ciphertext.txt


### To Do's

Trim newlines and whitespaces, abstract driver from program for flexibility,
allow user to specify encryption or decryption and output appropriately.
