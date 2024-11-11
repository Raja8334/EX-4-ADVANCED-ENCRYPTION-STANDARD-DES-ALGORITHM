# EX-4-ADVANCED-ENCRYPTION-STANDARD-DES-ALGORITHM

## Aim:
  To use Advanced Encryption Standard (AES) Algorithm for a practical application like URL Encryption.

## ALGORITHM: 
  1. AES is based on a design principle known as a substitution–permutation. 
  2. AES does not use a Feistel network like DES, it uses variant of Rijndael. 
  3. It has a fixed block size of 128 bits, and a key size of 128, 192, or 256 bits. 
  4. AES operates on a 4 × 4 column-major order array of bytes, termed the state

## PROGRAM: 
### ENCRYPTION:
```c
#include <stdio.h>
#include <string.h>

// Function to perform XOR operation for encryption
void aesEncrypt(const char *plaintext, const char *key, char *ciphertext) {
    for (int i = 0; i < 16; i++) {
        ciphertext[i] = plaintext[i] ^ key[i];
    }
}

int main() {
    char plaintext[16] = "HELLO_AES_TEST!!"; // 16-byte plaintext
    char key[16] = "AESKEY1234567890";      // 16-byte key
    char ciphertext[16];

    printf("Original Text: %s\n", plaintext);

    // Encrypt the plaintext
    aesEncrypt(plaintext, key, ciphertext);

    // Print the ciphertext in hexadecimal format
    printf("Encrypted Text (Hex): ");
    for (int i = 0; i < 16; i++) {
        printf("%02X ", (unsigned char)ciphertext[i]);
    }
    printf("\n");

    return 0;
}
```
### DECRYPTION:
```c
#include <stdio.h>
#include <string.h>

// Function to perform XOR operation for decryption
void aesDecrypt(const char *ciphertext, const char *key, char *decryptedText) {
    for (int i = 0; i < 16; i++) {
        decryptedText[i] = ciphertext[i] ^ key[i];
    }
}

int main() {
    char key[16] = "AESKEY1234567890"; // 16-byte key
    // Encrypted message (output from the encryption program)
    char ciphertext[16] = {0x09, 0x00, 0x1F, 0x0C, 0x1A, 0x45, 0x08, 0x55, 
                           0x1A, 0x1A, 0x07, 0x15, 0x00, 0x2F, 0x0C, 0x2D};
    char decryptedText[16];

    // Decrypt the ciphertext
    aesDecrypt(ciphertext, key, decryptedText);

    // Print the decrypted text
    printf("Decrypted Text: %s\n", decryptedText);

    return 0;
}
```
## OUTPUT:
### ENCRYPTION:
![image](https://github.com/user-attachments/assets/074355d7-7e69-4f99-9045-64977293f867)
### DECRYPTION:
![image](https://github.com/user-attachments/assets/8051a923-b5ad-4587-b66e-98f4ade61ca6)


## RESULT: 
The program is executed successfully.
