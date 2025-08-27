# Digital Signature & ECDH Tool Documentation

## Table of Contents
- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage Guide](#usage-guide)
- [Technical Details](#technical-details)
- [Security Considerations](#security-considerations)
- [Code Structure](#code-structure)
- [API Reference](#api-reference)
- [Examples](#examples)
- [Troubleshooting](#troubleshooting)
- [Contributing](#contributing)
- [License](#license)

## Overview

The Digital Signature & ECDH Tool is a comprehensive Python application that implements three fundamental cryptographic protocols:

1. **RSA Digital Signatures** - For message authentication and non-repudiation
2. **ECC Digital Signatures** - Elliptic Curve based signatures for efficiency
3. **ECDH Key Exchange** - Secure key agreement protocol

This tool provides both educational value and practical implementation of modern cryptographic techniques with an intuitive graphical user interface.

## Features

### ✨ Core Functionality
- **RSA Digital Signatures**: Generate, sign, and verify messages using RSA-2048/512
- **ECC Digital Signatures**: ECDSA using NIST P-256 curve
- **ECDH Key Exchange**: Secure shared secret establishment
- **Key Generation**: Automatic generation of all cryptographic key pairs
- **Message Hashing**: SHA-256 hashing for message integrity

### 🖥️ User Interface
- Clean, modern GUI built with Tkinter
- Real-time output display
- Interactive buttons with emojis for better UX
- Scrollable text areas for large outputs
- Information popup for ECDH explanation

### 🔒 Security Features
- Industry-standard curves and parameters
- Proper random number generation
- Secure key derivation functions
- Error handling for cryptographic operations

## Installation

### Prerequisites
- Python 3.7 or higher
- pip package manager

### Required Dependencies
```bash
pip install pycryptodome ecdsa
```

### Alternative Installation
```bash
# Clone or download the project
# Navigate to project directory
pip install -r requirements.txt  # if requirements.txt is provided
```

### System Requirements
- **OS**: Windows, macOS, Linux
- **RAM**: 256MB minimum
- **Storage**: 50MB for dependencies

## Usage Guide

### Starting the Application
```bash
python digital_signature_tool.py
```

### Step-by-Step Usage

#### 1. Generate Keys
1. Click **"🔑 Generate All Keys"**
2. View generated RSA, ECC, and ECDH keys in output window
3. Keys are automatically stored in memory for current session

#### 2. RSA Digital Signatures
1. Enter your message in the input text area
2. Click **"✍️ RSA Sign"** to create signature
3. Click **"✅ RSA Verify"** to verify the signature
4. View results in output window

#### 3. ECC Digital Signatures
1. Enter your message in the input text area
2. Click **"✍️ ECC Sign"** to create ECDSA signature
3. Click **"✅ ECC Verify"** to verify the signature
4. View results in output window

#### 4. ECDH Key Exchange
1. Click **"🔐 Generate ECDH Keys"** to create Alice and Bob's key pairs
2. Click **"🤝 ECDH Key Exchange"** to perform key agreement
3. Observe that both parties compute the same shared secret
4. View derived symmetric key for encryption

#### 5. Learn About ECDH
- Click **"ℹ️ ECDH Info"** for detailed explanation of the protocol

## Technical Details

### Cryptographic Algorithms

#### RSA Implementation
- **Key Size**: 512-bit (configurable to 1024/2048)
- **Public Exponent**: 65537 (standard)
- **Padding**: None (educational implementation)
- **Hash Function**: SHA-256

```python
# RSA Key Generation Process
p = getPrime(bits)  # First prime
q = getPrime(bits)  # Second prime
n = p * q           # Modulus
phi = (p-1) * (q-1) # Euler's totient
e = 65537           # Public exponent
d = e^(-1) mod phi  # Private exponent
```

#### ECC Implementation
- **Curve**: NIST P-256 (secp256r1)
- **Key Size**: 256-bit
- **Signature Algorithm**: ECDSA
- **Hash Function**: SHA-256 (built into ECDSA)

#### ECDH Implementation
- **Curve**: NIST P-256 (secp256r1)
- **Key Derivation**: SHA-256 based
- **Shared Secret**: X-coordinate of computed point
- **Security Level**: ~128-bit equivalent

### Mathematical Foundations

#### RSA Security
Based on the difficulty of factoring large composite numbers:
```
Given n = p × q, finding p and q is computationally infeasible
```

#### ECC Security
Based on the Elliptic Curve Discrete Logarithm Problem (ECDLP):
```
Given P and Q = kP on elliptic curve, finding k is computationally infeasible
```

#### ECDH Protocol
```
Alice: private key a, public key A = a×G
Bob: private key b, public key B = b×G
Shared Secret: S = a×B = b×A = (a×b)×G
```

## Security Considerations

### ⚠️ Important Warnings

1. **Educational Purpose**: This implementation is for learning. Use established libraries for production.

2. **Key Storage**: Keys are stored in memory only. Implement secure storage for real applications.

3. **Random Number Generation**: Uses system RNG. Consider hardware RNG for high-security applications.

4. **Side-Channel Attacks**: Implementation doesn't protect against timing or power analysis attacks.

### 🛡️ Security Best Practices

1. **Key Management**:
   - Generate new keys regularly
   - Never reuse RSA keys for encryption and signing
   - Store private keys securely

2. **Message Handling**:
   - Always hash messages before signing
   - Validate input data
   - Use proper encoding

3. **Implementation**:
   - Use constant-time operations
   - Implement proper error handling
   - Validate all cryptographic parameters

## Code Structure

### File Organization
```
digital_signature_tool.py
├── RSA Functions
│   ├── generate_rsa_keys()
│   ├── rsa_sign_message()
│   └── rsa_verify_signature()
├── ECC Functions
│   ├── ecc_sign_message()
│   └── ecc_verify_signature()
├── ECDH Functions
│   ├── generate_ecdh_keypair()
│   ├── ecdh_compute_shared_secret()
│   └── derive_key_from_shared_secret()
└── GUI Functions
    ├── Main Window Setup
    ├── Event Handlers
    └── Display Functions
```

### Key Classes and Functions

#### Core Cryptographic Functions
- `generate_rsa_keys(bits)`: Creates RSA key pairs
- `hash_message(message)`: SHA-256 message hashing
- `generate_ecc_keys()`: Creates ECC key pairs
- `generate_ecdh_keypair()`: Creates ECDH key pairs

#### GUI Functions
- `generate_keys_gui()`: GUI wrapper for key generation
- `rsa_sign_gui()`: GUI wrapper for RSA signing
- `ecdh_key_exchange_gui()`: GUI wrapper for ECDH

## API Reference

### RSA Functions

#### `generate_rsa_keys(bits=1024)`
Generates RSA key pair.

**Parameters:**
- `bits` (int): Key size in bits (default: 1024)

**Returns:**
- `dict`: Contains 'public' and 'private' key tuples

**Example:**
```python
keys = generate_rsa_keys(2048)
public_key = keys['public']   # (e, n)
private_key = keys['private'] # (d, n)
```

#### `rsa_sign_message(message, private_key, use_hash=True)`
Signs a message using RSA private key.

**Parameters:**
- `message` (str): Message to sign
- `private_key` (tuple): RSA private key (d, n)
- `use_hash` (bool): Whether to hash message (default: True)

**Returns:**
- `int`: Digital signature

#### `rsa_verify_signature(message, signature, public_key, use_hash=True)`
Verifies RSA signature.

**Parameters:**
- `message` (str): Original message
- `signature` (int): Signature to verify
- `public_key` (tuple): RSA public key (e, n)
- `use_hash` (bool): Whether message was hashed (default: True)

**Returns:**
- `bool`: True if signature is valid

### ECC Functions

#### `generate_ecc_keys()`
Generates ECC key pair using NIST P-256.

**Returns:**
- `dict`: Contains 'private' and 'public' keys

#### `ecc_sign_message(message, private_key)`
Signs message using ECDSA.

**Parameters:**
- `message` (str): Message to sign
- `private_key` (SigningKey): ECC private key

**Returns:**
- `bytes`: ECDSA signature

#### `ecc_verify_signature(message, signature, public_key)`
Verifies ECDSA signature.

**Parameters:**
- `message` (str): Original message
- `signature` (bytes): Signature to verify
- `public_key` (VerifyingKey): ECC public key

**Returns:**
- `bool`: True if signature is valid

### ECDH Functions

#### `generate_ecdh_keypair()`
Generates ECDH key pair.

**Returns:**
- `dict`: Contains 'private' and 'public' keys

#### `ecdh_compute_shared_secret(private_key, public_key)`
Computes ECDH shared secret.

**Parameters:**
- `private_key` (SigningKey): Local private key
- `public_key` (VerifyingKey): Remote public key

**Returns:**
- `bytes`: Shared secret (32 bytes)

#### `derive_key_from_shared_secret(shared_secret, info=b'')`
Derives symmetric key from shared secret.

**Parameters:**
- `shared_secret` (bytes): ECDH shared secret
- `info` (bytes): Additional context info

**Returns:**
- `bytes`: Derived key (32 bytes)

## Examples

### Example 1: Basic RSA Signing
```python
# Generate keys
keys = generate_rsa_keys(1024)
message = "Hello, World!"

# Sign message
signature = rsa_sign_message(message, keys['private'])

# Verify signature
is_valid = rsa_verify_signature(message, signature, keys['public'])
print(f"Signature valid: {is_valid}")
```

### Example 2: ECC Signing
```python
# Generate ECC keys
keys = generate_ecc_keys()
message = "Secure message"

# Sign and verify
signature = ecc_sign_message(message, keys['private'])
is_valid = ecc_verify_signature(message, signature, keys['public'])
print(f"ECC signature valid: {is_valid}")
```

### Example 3: ECDH Key Exchange
```python
# Alice and Bob generate key pairs
alice_keys = generate_ecdh_keypair()
bob_keys = generate_ecdh_keypair()

# Compute shared secrets
alice_secret = ecdh_compute_shared_secret(
    alice_keys['private'], 
    bob_keys['public']
)
bob_secret = ecdh_compute_shared_secret(
    bob_keys['private'], 
    alice_keys['public']
)

# Verify they match
print(f"Secrets match: {alice_secret == bob_secret}")

# Derive symmetric key
sym_key = derive_key_from_shared_secret(alice_secret, b'encryption')
```

## Troubleshooting

### Common Issues

#### Import Errors
```
ModuleNotFoundError: No module named 'Crypto'
```
**Solution**: Install dependencies
```bash
pip install pycryptodome ecdsa
```

#### Key Generation Fails
```
ValueError: Unable to generate prime
```
**Solution**: Reduce key size or restart application

#### GUI Not Responding
**Solution**: Close and restart application. Check system resources.

#### Signature Verification Fails
**Solution**: 
- Ensure message hasn't been modified
- Check that same keys are used for signing and verification
- Verify message encoding is consistent

### Performance Issues

#### Slow Key Generation
- RSA key generation with large bit sizes (>2048) can be slow
- Consider using smaller keys for testing
- ECC key generation is much faster

#### Memory Usage
- Keys are stored in memory during session
- Restart application if memory usage becomes high

### Platform-Specific Issues

#### Windows
- Ensure Python PATH is correctly set
- Some antivirus software may flag cryptographic operations

#### macOS
- May need to install tkinter separately: `brew install python-tk`

#### Linux
- Install tkinter: `sudo apt-get install python3-tk`

## Contributing

### Development Setup
1. Fork the repository
2. Create virtual environment: `python -m venv venv`
3. Activate environment: `source venv/bin/activate` (Linux/Mac) or `venv\Scripts\activate` (Windows)
4. Install dependencies: `pip install -r requirements.txt`

### Code Standards
- Follow PEP 8 style guidelines
- Add docstrings to all functions
- Include error handling
- Write unit tests for new features

### Security Review
- All cryptographic implementations must be reviewed
- No hardcoded keys or secrets
- Proper random number generation
- Input validation and sanitization

### Testing
```bash
# Run tests (if test suite exists)
python -m pytest tests/

# Manual testing checklist
- [ ] Key generation works
- [ ] RSA signing and verification
- [ ] ECC signing and verification  
- [ ] ECDH key exchange
- [ ] GUI responsiveness
- [ ] Error handling
```

## License

This project is provided for educational purposes. Use established cryptographic libraries for production applications.

### Disclaimer
This implementation is for learning and demonstration purposes only. It has not undergone security audits and should not be used in production environments where security is critical.

### References
- RFC 3447: RSA PKCS #1 v2.1
- RFC 5480: ECC Subject Public Key Info
- RFC 5915: ECC Private Key Structure  
- NIST SP 800-56A: ECDH Key Agreement
- FIPS 186-4: Digital Signature Standard

---

## Version History

- **v1.0.0**: Initial release with RSA and ECC signatures
- **v1.1.0**: Added ECDH key exchange functionality
- **v1.1.1**: Improved GUI and documentation

## Support

For questions, issues, or contributions:
- Create GitHub issues for bugs
- Submit pull requests for enhancements
- Check documentation for common solutions

---

*Last updated: May 2025*
