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

# This step will guide you through generating a PGP key pair, which includes both a private key and a public key.

1. **Run the following command to generate the PGP key pair:**

    ```bash
    gpg --full-generate-key
    ```

2. **Select the key type:**
    - When prompted, select the key type. For most users, **RSA** is the recommended choice. Choose **1** to select the RSA option.

3. **Choose the key size:**
    - Next, you will be asked to choose the key size. For stronger encryption, select **4096 bits** by typing **4096**. This is the recommended size for enhanced security.

4. **Set expiration date:**
    - You will then be prompted to set an expiration date for the key. You can either set a specific expiration date or choose **0** to keep it valid indefinitely.

5. **Enter your name and email:**
    - Provide your name and email address when prompted. This is how others will identify you when verifying your PGP key.

6. **Add an optional comment:**
    - You can enter an optional comment (e.g., your organization or purpose for the key) or leave it blank.

7. **Set a strong passphrase:**
    - Finally, set a strong passphrase to protect your private key. Make sure the passphrase is secure and not easily guessable.

After completing these steps, your PGP key pair (private and public keys) will be generated and stored in your keyring.


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
