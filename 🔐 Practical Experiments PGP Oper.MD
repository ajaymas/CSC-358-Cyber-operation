# 🔐 Practical Experiments: PGP Operations in Linux

This document provides step-by-step **PGP experiments** using **GnuPG (GPG)** on **Linux/macOS**.

# 🔥 What This Covers:

✅ **PGP Authentication** (Digital Signatures)  
✅ **PGP Confidentiality** (Encryption & Decryption)  
✅ **PGP Authentication + Confidentiality** (Combined Approach)  
✅ **PGP Compression** (Efficient Storage & Transmission)  
✅ **PGP Email Compatibility** (Encoding for Email)  
✅ **PGP Session Keys & Key Management**  

---

## 📌 **1. Setup: Install GnuPG (GPG)**
Install **GnuPG**, an open-source PGP implementation.

```bash
sudo apt install gnupg  # Linux (Debian/Ubuntu)
brew install gnupg      # macOS (Homebrew)
```

Verify installation:
```bash
gpg --version
```

---

## ✅ **2. PGP Authentication: Digital Signatures**
Generate a **PGP key pair** (private & public keys):
```bash
gpg --full-generate-key
```

List your generated keys:
```bash
gpg --list-keys
```

Sign a file:
```bash
gpg --clearsign message.txt
```

Verify the signature:
```bash
gpg --verify message.txt.asc
```

---

## 🔐 **3. PGP Confidentiality: Encryption & Decryption**
Export the public key to share:
```bash
gpg --export -a "Your Name" > public_key.asc
```

Encrypt a file using the recipient's public key:
```bash
gpg --encrypt --recipient "Recipient Name" secret.txt
```

Decrypt a file:
```bash
gpg --decrypt secret.txt.gpg
```

---

## 🔄 **4. PGP Authentication + Confidentiality (Signing & Encrypting)**
Sign and encrypt a message:
```bash
gpg --sign --encrypt --recipient "Recipient Name" confidential.txt
```

Decrypt and verify:
```bash
gpg --decrypt confidential.txt.gpg
```

---

## 📦 **5. PGP Compression (Efficient Storage & Transmission)**
Compress a file while signing:
```bash
gpg --sign --compress-algo ZIP data.txt
```

---

## 📧 **6. PGP Email Compatibility (ASCII Armoring for Email)**
Convert binary output to text (ASCII armor):
```bash
gpg --armor --export "Your Name" > public_key.asc
```

Encrypt a file with ASCII output:
```bash
gpg --armor --encrypt --recipient "Recipient Name" email.txt
```

Decrypt ASCII armored message:
```bash
gpg --decrypt email.txt.asc
```

---

## 🔑 **7. PGP Session Keys & Key Management**
Extract session key used in encryption:
```bash
gpg --show-session-key secret.txt.gpg
```

Delete a key pair:
```bash
gpg --delete-secret-and-public-key "Your Name"
```

Revoke a key:
```bash
gpg --gen-revoke "Your Name" > revoke.asc
```

---

## 🎯 **Conclusion**
This guide covers essential **PGP operations** for security, encryption, and key management in Linux/macOS using **GnuPG**. Experiment and integrate PGP into your security workflow! 🚀
