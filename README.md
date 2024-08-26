# SymmetricKeyEncryptionProject

This project was developed as a final individual assignment for the CS3750 Computer and Network Security class. It involves the creation of a simple symmetric encryption system consisting of three programs: KeyGen, Sender, and Receiver. These programs work together to securely transmit and receive encrypted data using symmetric key cryptography.

# Symmetric Encryption and Its Digital Signature

This project was developed as a final individual assignment for the CS3750 Computer and Network Security class. It demonstrates the use of symmetric encryption combined with RSA digital signatures to ensure both the confidentiality and integrity of a message. The system consists of three main programs: KeyGen, Sender, and Receiver.

## Project Overview

The project includes the following components:

### 1. KeyGen Program

The KeyGen program is responsible for generating and managing the necessary keys for encryption and decryption.

**Steps for Key Generation Program:**
- **Generate RSA Key Pairs**: The program creates a pair of RSA public and private keys for both the Sender (X) and the Receiver (Y).
- **Save RSA Keys**: The modulus and exponent of each key are extracted and saved into separate key files.
- **Generate Symmetric Key**: The user is prompted to input a 16-character string, which will be used as the symmetric key for AES encryption/decryption.

The generated keys are essential for the subsequent encryption and decryption processes.

### 2. Sender Program

The Sender program handles the encryption of the message using both RSA and AES encryption methods.

**Steps for Sender Program:**
- **Key Preparation**: The Sender’s private RSA key and the symmetric key are copied to the Sender’s directory (`Xprivate.key` and `symmetric.key`). The program reads these keys from their respective files.
- **Message Input**: The user is prompted to input the name of the message file that is to be encrypted.
- **Calculate SHA256 Hash**: The program reads the message file in 1024-byte chunks, calculating the SHA256 hash (digital digest) of the entire message. This hash is saved in a file named `message.dd`.
- **Digest Inversion Option**: The program asks the user whether they want to invert the first byte of the digital digest. This step allows for testing the integrity verification process.
- **RSA Encryption of Digest**: The SHA256 hash is encrypted using the Sender’s private key (`Xprivate.key`) to generate an RSA-encrypted digital signature. This step ensures the integrity of the message. The digital signature is saved in `message.ds-msg`.
- **Append Message**: The original message is appended to the `message.ds-msg` file piece by piece.
- **AES Encryption**: The program proceeds to encrypt the combined digital signature and message using the AES algorithm (`AES/ECB/PKCS5Padding`). The encrypted output is saved to a file named `message.aescipher`.

### 3. Receiver Program

The Receiver program is responsible for decrypting the encrypted message and verifying its integrity.

**Steps for Receiver Program:**
- **Key Preparation**: The `message.aescipher`, `symmetric.key`, and `Xpublic.key` files are copied into the Receiver’s directory. The program reads the necessary information from these files.
- **User Input**: The user is prompted to input the name of the output file where the decrypted message will be saved.
- **AES Decryption**: The program decrypts the `message.aescipher` file in 16-byte chunks using the symmetric key. The decrypted output is saved in `message.ds-msg`.
- **RSA Decryption**: The program reads the first 128 bytes from `message.ds-msg` to obtain the digital signature (`RSA-En(SHA256(M))`). It decrypts the signature using the Sender’s public key (`Xpublic.key`) to retrieve the original digital digest (`SHA256(M)`). The digest is saved in `message.dd`.
- **Message Integrity Verification**: The remaining bytes in `message.ds-msg` (the original message) are copied to the output file. The program then reads the message from the output file, recalculates the SHA256 hash, and compares it with the digital digest to verify the integrity of the message.
