# 🔐 User Authentication Lab (Guide + Student Worksheet)

This lab complements **Chapter 3 – User Authentication** by showing **hands-on exercises** in the terminal.  
Each section includes:
- **Concept & Explanation** (for teaching/demo)  
- **Commands** (to try in terminal)  
- **Student Worksheet Section** (questions + space for notes)  

---

## 1. Introduction to User Authentication

**Concept**  
Authentication = Identification (username) + Verification (password).  

**Explanation**  
System identifies you (`username`) and verifies with your password before granting access.

**Commands**
```bash
whoami     # shows current logged-in user
id         # shows UID, groups (identification)
```

**Student Worksheet**  
- What username does the system show for you?  
- What groups/roles are associated with your account?  

**Your Notes ...**

---

## 2. Basic Security Requirements (MFA & Replay Resistance)

**Concept**  
OTP prevents reuse of stolen credentials.

**Explanation**  
Every run generates a new code → prevents replay attacks.

**Commands**
```bash
sudo apt-get install oathtool -y
oathtool --totp -b "JBSWY3DPEHPK3PXP"   # generates OTP like Google Authenticator
```

**Student Worksheet**  
- What happens each time you run the command?  
- Why can’t this code be reused later?  

**Your Notes ...**

---

## 3. Password-Based Authentication

**Concept**  
System compares entered password with stored one.

**Explanation**  
System validates user identity using stored password.

**Commands**
```bash
passwd    # change your system password
su - user # switch user, requires password
```

**Student Worksheet**  
- What does the system ask for when you switch users?  
- Why is this important for security?  

**Your Notes ...**

---

## 4. Password Vulnerabilities (Dictionary Attack)

**Concept**  
Weak passwords can be cracked easily.

**Explanation**  
John cracks "password" instantly → shows why strong passwords are risky.

**Commands**
```bash
echo "user:5f4dcc3b5aa765d61d8327deb882cf99" > passwd.txt
john passwd.txt --format=raw-md5
```

**Student Worksheet**  
- Which password was cracked?  
- Why was it cracked so quickly?  

**Your Notes ...**

---

## 5. Hashed & Salted Passwords

**Concept**  
Adding salt makes hashes unique.

**Explanation**  
Same password looks different when salted → prevents dictionary attacks.

**Commands**
```bash
echo -n "mypassword" | md5sum       # hash only
echo -n "mysaltmypassword" | md5sum # hash with salt
```

**Student Worksheet**  
- What differences do you notice in outputs?  
- Why does salt improve security?  

**Your Notes ...**

---

## 6. Tokens: Memory & Smart Cards

**Concept**  
Something you have (ATM card, USB token).

**Explanation**  
Smart tokens are recognized by the system and used for authentication.

**Commands**
```bash
lsusb   # lists connected USB devices
```

**Student Worksheet**  
- What devices are listed?  
- How could a USB token be used in login?  

**Your Notes ...**

---

## 7. Smart Cards & eID

**Concept**  
Smart cards store identity securely.

**Explanation**  
System scans and detects smartcard → authentication handshake ready.

**Commands**
```bash
pcsc_scan
```

**Student Worksheet**  
- Was a card detected?  
- How is this different from a password?  

**Your Notes ...**

---

## 8. Biometric Authentication

**Concept**  
Authenticate using fingerprint or face.

**Explanation**  
Biometric replaces password login.

**Commands**
```bash
fprintd-enroll   # enroll fingerprint
fprintd-verify   # verify fingerprint
```

**Student Worksheet**  
- How does the system verify your fingerprint?  
- Can another person log in with theirs? Why/why not?  

**Your Notes ...**

---

## 9. Remote User Authentication

**Concept**  
Authentication over network with risks.

**Explanation**  
Key-based SSH authentication is stronger than password-only login.

**Commands**
```bash
ssh user@remote_host          # password login
ssh-keygen                    # generate key pair
ssh-copy-id user@remote_host  # copy public key
ssh user@remote_host          # now logs in without password
```

**Student Worksheet**  
- What difference did you observe between password login and key-based login?  
- Why is key-based login considered stronger?  

**Your Notes ...**

---

## 10. Case Study: ATM Security

**Concept**  
ATM uses card + PIN; must secure PIN entry.

**Explanation**  
`-s` hides PIN while typing → just like ATM keypad.

**Commands**
```bash
read -s -p "Enter PIN: " pin
echo
echo "PIN accepted: $pin"
```

**Student Worksheet**  
- What happens when you type your PIN?  
- Why doesn’t it appear on screen?  

**Your Notes ...**

---

# ✅ Summary
- **whoami/id** → Identification  
- **passwd/su** → Password verification  
- **oathtool** → MFA & replay resistance  
- **john** → Password cracking  
- **md5sum with salt** → Stronger hashes  
- **lsusb/pcsc_scan** → Tokens & smart cards  
- **fprintd** → Biometrics  
- **ssh + keys** → Remote authentication  
- **read -s** → ATM PIN simulation  

---

# 🚀 Lab Extension Ideas
- Implement a Python login system (username+password).  
- Add OTP verification with pyotp.  
- Try cracking weak hashes chosen by students with John.  
- Group project: multi-factor authentication demo (password + OTP + fingerprint).  

---

# 📝 Reflection (Student Notes)
1. Which authentication method felt most secure to you? Why?  
2. Which vulnerability surprised you the most?  
3. How would you design a multi-factor authentication system using what you learned?  

**Your Notes ...**
