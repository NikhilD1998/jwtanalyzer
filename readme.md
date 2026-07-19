# 🔐 JWT Analyzer

A command-line JWT (JSON Web Token) security analysis tool built in Python.

JWT Analyzer helps developers, security engineers, penetration testers, and SOC analysts inspect JWTs, identify common security issues, verify signatures, and generate security assessment reports.

---

## Features

### JWT Decoding

- Decode JWT header and payload
- Pretty JSON output
- Read JWT from command line or file

---

### Security Analysis

Performs automated security checks including:

- Algorithm validation
- Detection of `alg=none`
- Token type validation
- Subject (`sub`) validation
- Issuer (`iss`) validation
- Audience (`aud`) validation
- JWT ID (`jti`) validation
- Expiration (`exp`) validation
- Issued At (`iat`) validation
- Not Before (`nbf`) validation
- Token size analysis
- Sensitive claim detection
- Privileged token detection
- Token lifetime analysis

---

### Security Scoring

Every token receives a weighted security score.

Example:

```
Score      : 55/100
Risk Level : HIGH
```

Risk Levels

|  Score | Risk     |
| -----: | -------- |
| 90-100 | LOW      |
|  75-89 | MEDIUM   |
|  50-74 | HIGH     |
|   0-49 | CRITICAL |

---

### Signature Verification

Supports:

- HS256
- HS384
- HS512
- RS256
- RS384
- RS512

Supports verification using:

- Shared Secret
- RSA Public Key (.pem)

---

### Report Generation

Export analysis as:

- JSON
- Markdown

Perfect for documentation and security assessments.

---

### Rich CLI Interface

Built using Rich for:

- Tables
- Panels
- Colored output
- JSON rendering

---

# Project Structure

```
jwt-analyzer/
│
├── analyzer/
│   ├── analyzer.py
│   ├── parser.py
│   ├── verifier.py
│   ├── renderer.py
│   ├── report.py
│   ├── scorer.py
│   ├── checks.py
│   └── utils.py
│
├── samples/
│
├── main.py
├── requirements.txt
└── README.md
```

---

# Installation

Clone the repository

```bash
git clone https://github.com/yourusername/jwt-analyzer.git

cd jwt-analyzer
```

Create virtual environment

Windows

```bash
python -m venv venv

venv\Scripts\activate
```

Linux/macOS

```bash
python3 -m venv venv

source venv/bin/activate
```

Install dependencies

```bash
pip install -r requirements.txt
```

---

# Usage

## Decode JWT

```bash
python main.py decode "<JWT>"
```

Read from file

```bash
python main.py decode --file samples/hs256.jwt
```

---

## Analyze JWT

```bash
python main.py analyze "<JWT>"
```

Read from file

```bash
python main.py analyze --file samples/admin.jwt
```

Export JSON report

```bash
python main.py analyze --file samples/admin.jwt --json report.json
```

Export Markdown report

```bash
python main.py analyze --file samples/admin.jwt --md report.md
```

---

## Verify HMAC JWT

```bash
python main.py verify "<JWT>" --key mysecret
```

---

## Verify RSA JWT

```bash
python main.py verify "<JWT>" --key public.pem
```

---

# Example Output

## Decode

```
JWT Header

{
    "alg": "HS256",
    "typ": "JWT"
}
```

---

## Security Analysis

```
Security Score

Score      : 55/100

Risk Level : HIGH

Critical Findings : 0
High Findings     : 0
Medium Findings   : 4
Low Findings      : 3
```

---

## Signature Verification

```
Signature Verification

Algorithm : RS256

Key Type  : RSA Public Key

Status    : PASS

Message   : Valid RS256 signature.
```

---

# Security Checks

| Check            | Description                        |
| ---------------- | ---------------------------------- |
| Algorithm        | Detect insecure signing algorithms |
| Token Type       | Validate JWT type                  |
| Subject          | Validate subject claim             |
| Issuer           | Validate issuer claim              |
| Audience         | Validate audience claim            |
| JWT ID           | Detect missing token identifier    |
| Expiration       | Detect missing or expired tokens   |
| Issued At        | Validate issued time               |
| Not Before       | Validate activation time           |
| Token Size       | Detect oversized JWTs              |
| Sensitive Claims | Detect secrets inside payload      |
| Privileges       | Detect privileged/admin tokens     |
| Token Lifetime   | Calculate token lifetime           |

---

# Sample Tokens

The project includes sample JWTs for testing.

```
samples/

admin.jwt

alg_none.jwt

empty.jwt

future.jwt

full_claims.jwt

hs256.jwt

oversized.jwt

sensitive.jwt
```

---

# Technologies Used

- Python 3
- PyJWT
- Rich
- Cryptography

---

# Author

Developed as a cybersecurity portfolio project demonstrating:

- JWT internals
- Authentication security
- Cryptography
- Signature verification
- Secure coding practices
- Python CLI application development

---

# License

MIT License
