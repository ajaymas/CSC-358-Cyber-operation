
# Linux Hands-on Lab: RSA and Elliptic Curve Cryptography

This lab demonstrates RSA and EC encryption/decryption with different key sizes and modes using Linux commands (OpenSSL). It includes reproducible exercises and mini CTF-style tasks.

## Prep: create a lab directory and check OpenSSL
```bash
mkdir -p ~/crypto_lab && cd ~/crypto_lab
openssl version
```
Explanation:
- `mkdir -p ~/crypto_lab && cd ~/crypto_lab` — make a reproducible working folder and change into it.
- `openssl version` — shows installed OpenSSL version so you know which CLI features are available.

## PART A — RSA

### 1) Create a small plaintext and a larger plaintext
```bash
cat > small_plain.txt <<'EOF'
RSA test — small message: Hello, student!
EOF

cat > large_plain.txt <<'EOF'
This is a larger plaintext used to demonstrate hybrid encryption with RSA + AES.
Repeat a few times so the file size exceeds RSA block size limits.
Line2: cryptography is fun.
Line3: Ajay Kumar — Network Security Monitoring Lab.
EOF
```
Explanation:
- `cat > filename <<'EOF' ... EOF` writes a reproducible plaintext file. `small_plain.txt` is short; `large_plain.txt` is used for hybrid encryption.

### 2) Generate RSA private keys (1024, 2048, 4096) and public keys
```bash
# RSA 1024
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:1024 -out rsa1024_priv.pem
openssl rsa -in rsa1024_priv.pem -pubout -out rsa1024_pub.pem

# RSA 2048
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:2048 -out rsa2048_priv.pem
openssl rsa -in rsa2048_priv.pem -pubout -out rsa2048_pub.pem

# RSA 4096
openssl genpkey -algorithm RSA -pkeyopt rsa_keygen_bits:4096 -out rsa4096_priv.pem
openssl rsa -in rsa4096_priv.pem -pubout -out rsa4096_pub.pem
```
Explanation:
- `openssl genpkey` generates an RSA private key.
- `openssl rsa -pubout` extracts the public key.

### 3) RSA direct encryption/decryption (OAEP & PKCS#1 v1.5)

#### OAEP
```bash
openssl pkeyutl -encrypt -inkey rsa2048_pub.pem -pubin -in small_plain.txt -out small_rsa2048_oaep.bin -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256

openssl pkeyutl -decrypt -inkey rsa2048_priv.pem -in small_rsa2048_oaep.bin -out small_rsa2048_oaep.dec -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256

diff small_plain.txt small_rsa2048_oaep.dec && echo "OAEP decrypt OK"
```
Explanation:
- OAEP padding is modern and secure; decryption verifies equality.

#### PKCS#1 v1.5
```bash
openssl pkeyutl -encrypt -inkey rsa2048_pub.pem -pubin -in small_plain.txt -out small_rsa2048_pkcs1.bin -pkeyopt rsa_padding_mode:pkcs1

openssl pkeyutl -decrypt -inkey rsa2048_priv.pem -in small_rsa2048_pkcs1.bin -out small_rsa2048_pkcs1.dec -pkeyopt rsa_padding_mode:pkcs1

diff small_plain.txt small_rsa2048_pkcs1.dec && echo "PKCS#1 v1.5 decrypt OK"
```
Explanation:
- PKCS#1 v1.5 is legacy; decryption verifies equality.

### 4) RSA hybrid encryption for large data (AES + RSA)

#### Encrypt (sender)
```bash
openssl rand -hex 32 > aes_key.hex
openssl rand -hex 16 > iv.hex

openssl enc -aes-256-cbc -in large_plain.txt -out large_plain.aes.enc -K "$(tr -d '
' < aes_key.hex)" -iv "$(tr -d '
' < iv.hex)"

openssl pkeyutl -encrypt -inkey rsa2048_pub.pem -pubin -in aes_key.hex -out aes_key.hex.rsa.enc -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256
```
Explanation:
- Generates AES key & IV, encrypts the file with AES, encrypts AES key with RSA.

#### Decrypt (receiver)
```bash
openssl pkeyutl -decrypt -inkey rsa2048_priv.pem -in aes_key.hex.rsa.enc -out aes_key_decrypted.hex -pkeyopt rsa_padding_mode:oaep -pkeyopt rsa_oaep_md:sha256

openssl enc -d -aes-256-cbc -in large_plain.aes.enc -out large_plain_decrypted.txt -K "$(tr -d '
' < aes_key_decrypted.hex)" -iv "$(tr -d '
' < iv.hex)"

diff large_plain.txt large_plain_decrypted.txt && echo "Hybrid decrypt OK"
```
Explanation:
- Decrypts AES key using RSA, then decrypts file using AES.

---

## PART B — Elliptic Curve Cryptography (EC)

### 1) Generate EC keypairs
```bash
openssl ecparam -name prime256v1 -genkey -noout -out ec_prime256_priv.pem
openssl ec -in ec_prime256_priv.pem -pubout -out ec_prime256_pub.pem

openssl ecparam -name secp384r1 -genkey -noout -out ec_secp384_priv.pem
openssl ec -in ec_secp384_priv.pem -pubout -out ec_secp384_pub.pem

openssl ecparam -name secp521r1 -genkey -noout -out ec_secp521_priv.pem
openssl ec -in ec_secp521_priv.pem -pubout -out ec_secp521_pub.pem
```
Explanation:
- Generates EC private & public keys for multiple curves.

### 2) ECIES-style encryption (ephemeral ECDH + AES)
```bash
printf "ECIES-style test message — secret lab flag: FLAG{ec_demo}
" > ec_plain.txt

openssl ecparam -name prime256v1 -genkey -noout -out eph_priv.pem
openssl ec -in eph_priv.pem -pubout -out eph_pub.pem

openssl pkeyutl -derive -inkey eph_priv.pem -peerkey ec_prime256_pub.pem -out shared_eph_rec.bin

openssl dgst -sha256 -binary shared_eph_rec.bin > symkey.bin
xxd -p -c 256 symkey.bin > symkey.hex

openssl rand -hex 16 > iv.hex

openssl enc -aes-256-cbc -in ec_plain.txt -out ec_plain.aes.enc -K "$(tr -d '
' < symkey.hex)" -iv "$(tr -d '
' < iv.hex)"
```
Explanation:
- Ephemeral EC key + recipient public key to derive shared secret.
- SHA-256 hash as symmetric AES key.
- Encrypt plaintext with AES-256-CBC.

### 3) Decrypt (receiver)
```bash
openssl pkeyutl -derive -inkey ec_prime256_priv.pem -peerkey eph_pub.pem -out shared_rec.bin

openssl dgst -sha256 -binary shared_rec.bin > symkey_recv.bin
xxd -p -c 256 symkey_recv.bin > symkey_recv.hex

cmp symkey.bin symkey_recv.bin && echo "Derived symmetric keys are identical"

openssl enc -d -aes-256-cbc -in ec_plain.aes.enc -out ec_plain_decrypted.txt -K "$(tr -d '
' < symkey_recv.hex)" -iv "$(tr -d '
' < iv.hex)"

cat ec_plain_decrypted.txt
```
Explanation:
- Receiver derives the same symmetric key using their private key.
- Decrypt AES ciphertext to recover plaintext.

---

# Mini CTF Tasks

### RSA CTF 1
**Goal:** Recover plaintext from hybrid encryption (RSA-1024 OAEP + AES-256).  
**Hints:** Decrypt RSA-encrypted AES key, then decrypt AES ciphertext.

### RSA CTF 2
**Goal:** Recover plaintext from PKCS#1 v1.5 RSA-1024 encryption.  
**Hints:** Use `openssl pkeyutl -decrypt ... -pkeyopt rsa_padding_mode:pkcs1`.

### ECC CTF 1
**Goal:** Using receiver private key, derive AES key and decrypt ECIES-style ciphertext.  
**Hints:** Use `openssl pkeyutl -derive` + SHA-256 + AES decryption.

### ECC CTF 2
**Goal:** Analyze two ciphertexts encrypted with the same ephemeral key; observe why key reuse is dangerous.  
**Hints:** Compare derived AES keys and decrypt both messages.

---

# Cleanup
```bash
cd ~
# rm -rf ~/crypto_lab  # optional
```
