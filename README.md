# RSA Encryption Tool

## Overview
The RSA Encryption Tool is a simple application for encrypting and decrypting messages using RSA public-key cryptography. It allows users to generate RSA key pairs, load existing keys, and perform encryption and decryption operations.

## Features
- Generate RSA public and private keys.
- Encrypt messages using a public key.
- Decrypt messages using a private key.
- Save encrypted and decrypted messages to files.
- User-friendly GUI built with GTK.

## Requirements
- C compiler (e.g., `gcc`)
- GTK development libraries
- OpenSSL development libraries

### On Ubuntu, you can install the required dependencies using:
```bash
sudo apt update
sudo apt install build-essential libgtk-3-dev libssl-dev
Building the Application
To build the application, follow these steps:

Clone the repository:

bash
Copy code
git clone <repository-url>
cd <repository-folder>
Compile the source code:

bash
Copy code
gcc `pkg-config --cflags gtk+-3.0` -o rsa_encryption_tool rsa_encryption_tool.c `pkg-config --libs gtk+-3.0` -lssl -lcrypto
Usage
Run the application:

bash
Copy code
./rsa_encryption_tool
Generating Keys:

Click the "Generate Keys" button to create a new RSA key pair (public.pem and private.pem).
Encrypting a Message:

Enter the message you want to encrypt in the text entry field.
Click the "Encrypt" button to encrypt the message. The encrypted message will be saved to encrypted.txt.
Decrypting a Message:

Enter the hex-encoded encrypted message in the text entry field.
Click the "Decrypt" button to decrypt the message. The decrypted message will be saved to decrypted.txt.
Reloading Keys:

Click the "Reload Keys" button to load existing keys from public.pem and private.pem.
About:

Click the "About" button to see information about the application.
Key Files
public.pem: The public key file.
private.pem: The private key file.
encrypted.txt: The file that contains the encrypted message.
decrypted.txt: The file that contains the decrypted message.
License
This project is licensed under the MIT License. See the LICENSE file for details.

Acknowledgements
This application uses OpenSSL for cryptographic functions and GTK for the graphical user interface.
markdown
Copy code

### How to Use This `README.md`
1. **Repository URL**: Replace `<repository-url>` with the actual URL of your project repository (e.g., GitHub link).
2. **Repository Folder**: Replace `<repository-folder>` with the name of your project folder after cloning.
3. **Licensing**: Adjust the licensing section as necessary based on your actual license.

You can add more sections if needed, such as troubleshooting tips or contribution guidelines. Let me know if you need further modifications!
