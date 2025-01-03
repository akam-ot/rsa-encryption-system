# RSA Encryption/Decryption System

A Python GUI application implementing RSA encryption and decryption algorithm. Developed as part of a Cryptography course assignment.

## Features

- RSA key generation with configurable key sizes (256, 512, 1024 bits)
- Message encryption using RSA public key
- Message decryption using RSA private key
- Save and load key pairs
- Full Unicode text support
- User-friendly GUI with step-by-step process display
- Status updates for all operations
- Error handling and input validation

## Prerequisites

- Python 3.x
- Required packages:
  - sympy
  - tkinter (usually comes with Python)

## Installation

1. Clone the repository:
```bash
git clone https://github.com/akam-ot/rsa-encryption-system.git
cd rsa-encryption-system
```

2. Install required packages:
```bash
pip install -r requirements.txt
```

## Usage

1. Run the program:
```bash
python src/rsa_app.py
```

2. Using the application:
   - Select key size and generate keys in the "Key Generation" tab
   - Save keys for later use if needed
   - Enter a message in the "Encryption" tab to encrypt
   - Use the "Decryption" tab to decrypt messages

## Features in Detail

### Key Generation
- Choose from multiple key sizes
- View generated prime numbers and key components
- Save keys to file for later use
- Load previously saved keys

### Encryption
- Encrypt messages using public key
- Support for Unicode characters
- Message size validation
- Base64 encoded output

### Decryption
- Decrypt messages using private key
- Automatic handling of Base64 encoding
- Error detection for invalid inputs

## Educational Purpose

This implementation is for educational purposes and demonstrates:
- RSA algorithm principles
- Public-key cryptography concepts
- Number theory applications
- GUI development in Python

## Note

This is an educational implementation to understand RSA concepts. For real-world applications, use established cryptographic libraries and follow current security best practices.
