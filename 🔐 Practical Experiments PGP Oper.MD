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

## This step will guide you through generating a PGP key pair, which includes both a private key and a public key.

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
```


# 🛠 Experiment 1: PGP Authentication (Digital Signature)

## Objective

Verify message authenticity using SHA-1 hashing and RSA digital signatures.

## Steps

1️⃣ **Sender Creates a Message**
```
echo "This is a confidential document." > message.txt
```

2️⃣ **Generate SHA-1 Hash of Message**
```
sha1sum message.txt > message_hash.txt
```
- Generates a 160-bit SHA-1 hash.

3️⃣ **Encrypt Hash with Sender’s Private Key (Sign Message)**
```
gpg --output message.sig --sign message.txt
```
- Encrypts the hash with sender’s private key (RSA).
- Creates message.sig (digitally signed message).

4️⃣ **Send message.txt and message.sig to the Receiver**

5️⃣ **Receiver Verifies the Signature**
```
gpg --verify message.sig message.txt
```
- Extracts the signature and verifies it with sender’s public key.

✅ If hash matches, the message is authentic.




# Experiment 2: PGP Confidentiality (Encryption & Decryption)

## Objective

Encrypt message with session key and protect it using RSA.

## Steps

1️⃣ **Sender Generates a Message**
```bash
echo "Confidential report: Project X details" > secret_message.txt
```

2️⃣ **Encrypt Message Using Receiver’s Public Key**
```bash
gpg --output secret_message.gpg --encrypt --recipient receiver@example.com secret_message.txt
```
- Encrypts using CAST-128 / IDEA / 3DES.
- Generates a 128-bit session key.
- Encrypts session key using receiver’s public key.

3️⃣ **Send secret_message.gpg to the Receiver**

4️⃣ **Receiver Decrypts the Message**
```bash
gpg --output decrypted_message.txt --decrypt secret_message.gpg
```
- Decrypts session key with receiver’s private key.
- Uses session key to decrypt the message.

✅ Receiver reads the original message!

---

# 🔐 Experiment 3: Authentication + Confidentiality

## Objective

Sign & encrypt a message for both authenticity & confidentiality.

## Steps

1️⃣ **Sender Signs the Message**
```bash
gpg --output signed_message.txt --sign secret_message.txt
```
- Signs the message by attaching a digital signature.

2️⃣ **Encrypt the Signed Message**
```bash
gpg --output secure_message.gpg --encrypt --recipient receiver@example.com signed_message.txt
```
- Encrypts both message & signature.
- Encrypts session key using RSA.

3️⃣ **Send secure_message.gpg to the Receiver**

4️⃣ **Receiver Decrypts & Extracts the Signed Message**
```bash
gpg --output decrypted_signed_message.txt --decrypt secure_message.gpg
```

5️⃣ **Receiver Verifies the Signature**
```bash
gpg --verify decrypted_signed_message.txt
```
- Ensures the sender actually signed the message.

✅ Ensures both privacy & authenticity.



# Experiment 2: PGP Confidentiality (Encryption & Decryption)

## Objective

Encrypt message with session key and protect it using RSA.

## Steps

1️⃣ **Sender Generates a Message**
```bash
echo "Confidential report: Project X details" > secret_message.txt
```

2️⃣ **Encrypt Message Using Receiver’s Public Key**
```bash
gpg --output secret_message.gpg --encrypt --recipient receiver@example.com secret_message.txt
```
- Encrypts using CAST-128 / IDEA / 3DES.
- Generates a 128-bit session key.
- Encrypts session key using receiver’s public key.

3️⃣ **Send secret_message.gpg to the Receiver**

4️⃣ **Receiver Decrypts the Message**
```bash
gpg --output decrypted_message.txt --decrypt secret_message.gpg
```
- Decrypts session key with receiver’s private key.
- Uses session key to decrypt the message.

✅ Receiver reads the original message!

---

# 🔐 Experiment 3: Authentication + Confidentiality

## Objective

Sign & encrypt a message for both authenticity & confidentiality.

## Steps

1️⃣ **Sender Signs the Message**
```bash
gpg --output signed_message.txt --sign secret_message.txt
```
- Signs the message by attaching a digital signature.

2️⃣ **Encrypt the Signed Message**
```bash
gpg --output secure_message.gpg --encrypt --recipient receiver@example.com signed_message.txt
```
- Encrypts both message & signature.
- Encrypts session key using RSA.

3️⃣ **Send secure_message.gpg to the Receiver**

4️⃣ **Receiver Decrypts & Extracts the Signed Message**
```bash
gpg --output decrypted_signed_message.txt --decrypt secure_message.gpg
```

5️⃣ **Receiver Verifies the Signature**
```bash
gpg --verify decrypted_signed_message.txt
```
- Ensures the sender actually signed the message.

✅ Ensures both privacy & authenticity.
