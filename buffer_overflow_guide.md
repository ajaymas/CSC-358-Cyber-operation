# Buffer Overflow: Concise Teaching Guide with Terminal Practice

## Introduction to Buffer Overflow

### Key Points:
- **Definition**: Writing more data to buffer than allocated space
- **First major attack**: Morris Worm (1988)
- **Still relevant**: Legacy code + careless programming
- **Impact**: System crash or attacker control

### Terminal Practice:
```bash
# Setup workspace
mkdir ~/buffer-lab && cd ~/buffer-lab

# Check your system
uname -a
gcc --version
```

---

## What is a Buffer?

### Key Points:
- **Buffer**: Temporary storage area in memory
- **Fixed size**: Allocated at compile time or runtime
- **Common uses**: Storing user input, file data, network packets

### Terminal Practice:
```bash
# Create simple buffer example
cat > buffer_basic.c << 'EOF'
#include <stdio.h>
int main() {
    char buffer[10];  // 10-byte buffer
    printf("Buffer size: %lu bytes\n", sizeof(buffer));
    printf("Buffer address: %p\n", buffer);
    return 0;
}
EOF

gcc -o buffer_basic buffer_basic.c
./buffer_basic
```

**Output Explanation:**
- Size shows allocated bytes
- Address shows memory location

---

## Memory Layout of a Process

### Key Points:
- **Stack**: Local variables, function calls (grows DOWN)
- **Heap**: Dynamic allocation (grows UP)
- **Data**: Global/static variables
- **Text**: Program code (read-only)

### Terminal Practice:
```bash
cat > memory_map.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>

int global = 1;

int main() {
    int stack = 2;
    int *heap = malloc(sizeof(int));
    *heap = 3;
    
    printf("Text (code):   %p\n", main);
    printf("Global data:   %p\n", &global);
    printf("Heap:          %p\n", heap);
    printf("Stack:         %p\n", &stack);
    
    free(heap);
    return 0;
}
EOF

gcc -o memory_map memory_map.c
./memory_map
```

**Key Observation**: Addresses go from LOW (text) to HIGH (stack)

---

## Stack Frame Structure

### Key Points:
- **Return address**: Where to return after function completes
- **Saved frame pointer**: Previous stack frame location
- **Local variables**: Function's local data
- **Parameters**: Function arguments

### Terminal Practice:
```bash
cat > stack_demo.c << 'EOF'
#include <stdio.h>

void func(int a, int b) {
    int local = 99;
    printf("Inside func:\n");
    printf("  param a: %p\n", &a);
    printf("  param b: %p\n", &b);
    printf("  local:   %p\n", &local);
}

int main() {
    int x = 10;
    printf("In main: %p\n", &x);
    func(5, 10);
    return 0;
}
EOF

gcc -o stack_demo stack_demo.c
./stack_demo
```

**Key Observation**: Stack addresses decrease as you go deeper into function calls

---

## Basic Buffer Overflow Example

### Key Points:
- **Overflow**: Writing past buffer boundary
- **Consequence**: Overwrites adjacent memory
- **Variables affected**: Can corrupt nearby data

### Terminal Practice:
```bash
cat > overflow1.c << 'EOF'
#include <stdio.h>
#include <string.h>

int main() {
    int authenticated = 0;
    char password[8];
    
    printf("Enter password: ");
    gets(password);  // UNSAFE!
    
    printf("Password: %s\n", password);
    printf("Authenticated: %d\n", authenticated);
    
    if(authenticated) {
        printf("🔓 ACCESS GRANTED!\n");
    } else {
        printf("❌ ACCESS DENIED\n");
    }
    return 0;
}
EOF

gcc -o overflow1 overflow1.c -Wno-deprecated-declarations
```

**Test Cases:**
```bash
# Normal input
echo "pass" | ./overflow1

# Exact fit
echo "12345678" | ./overflow1

# OVERFLOW - corrupts authenticated variable
echo "AAAAAAAAAAAAAA" | ./overflow1
```

**What Happened?**
- Input > 8 bytes overwrites `authenticated` variable
- `authenticated` becomes non-zero
- Access granted without correct password!

---

## Memory Corruption Visualization

### Key Points:
- Variables stored consecutively in memory
- Buffer overflow writes into next variable's space
- Can corrupt data, pointers, or control flow

### Terminal Practice:
```bash
cat > corruption.c << 'EOF'
#include <stdio.h>
#include <string.h>

int main() {
    int val1 = 0x11111111;
    int val2 = 0x22222222;
    char buffer[8];
    int val3 = 0x33333333;
    
    printf("BEFORE:\n");
    printf("val1=%08x  val2=%08x  val3=%08x\n", val1, val2, val3);
    
    // Overflow the buffer
    strcpy(buffer, "AAAAAAAAABBBBCCCC");
    
    printf("\nAFTER:\n");
    printf("val1=%08x  val2=%08x  val3=%08x\n", val1, val2, val3);
    return 0;
}
EOF

gcc -o corruption corruption.c
./corruption
```

**Key Observation**: 
- Values change to ASCII codes (0x41='A', 0x42='B', 0x43='C')
- Shows how overflow corrupts adjacent memory

---

## Unsafe C Functions

### Key Points:
- **gets()**: No size checking
- **strcpy()**: No bounds checking
- **sprintf()**: Can overflow destination
- **strcat()**: Can overflow destination

### Terminal Practice:
```bash
cat > unsafe_funcs.c << 'EOF'
#include <stdio.h>
#include <string.h>

void demo_strcpy() {
    char dest[5];
    char src[] = "OVERFLOW!";
    printf("strcpy with 5-byte dest, 9-byte src\n");
    strcpy(dest, src);  // OVERFLOW!
}

void demo_safe() {
    char dest[5];
    char src[] = "OVERFLOW!";
    printf("\nstrncpy with size limit\n");
    strncpy(dest, src, sizeof(dest)-1);
    dest[4] = '\0';
    printf("Result: %s\n", dest);
}

int main() {
    // demo_strcpy();  // Uncomment to crash
    demo_safe();
    return 0;
}
EOF

gcc -o unsafe_funcs unsafe_funcs.c
./unsafe_funcs
```

**Safe vs Unsafe:**
| Unsafe | Safe Alternative |
|--------|-----------------|
| gets() | fgets() |
| strcpy() | strncpy() |
| strcat() | strncat() |
| sprintf() | snprintf() |

---

## Stack Smashing

### Key Points:
- **Target**: Overwrite return address on stack
- **Goal**: Redirect execution to attacker code
- **Method**: Overflow local buffer to reach return address

### Terminal Practice:
```bash
cat > stack_smash.c << 'EOF'
#include <stdio.h>
#include <string.h>

void secret() {
    printf("🚨 SECRET FUNCTION EXECUTED!\n");
}

void vulnerable(char *str) {
    char buffer[8];
    strcpy(buffer, str);  // OVERFLOW!
}

int main(int argc, char *argv[]) {
    printf("Secret function at: %p\n", secret);
    if(argc > 1) {
        vulnerable(argv[1]);
    }
    printf("Normal execution\n");
    return 0;
}
EOF

gcc -o stack_smash stack_smash.c -fno-stack-protector
```

**Test:**
```bash
./stack_smash "OK"                    # Normal
./stack_smash $(python3 -c "print('A'*50)")  # Crash
```

**Use GDB to see stack:**
```bash
gdb ./stack_smash
(gdb) break vulnerable
(gdb) run AAAA
(gdb) info frame
(gdb) x/20x $rsp
```

---

## 9: Shellcode Basics

### Key Points:
- **Shellcode**: Attacker's malicious code
- **Injected**: Via buffer overflow
- **Executed**: When control hijacked
- **Goal**: Spawn shell, create backdoor, etc.

### Terminal Practice:
```bash
# Simple shellcode example (educational)
cat > shellcode_demo.c << 'EOF'
#include <stdio.h>
#include <string.h>

// This is a NOP sled (0x90 = NOP instruction)
unsigned char code[] = 
    "\x90\x90\x90\x90"  // NOP sled
    "\x31\xc0"          // xor eax, eax
    "\x50"              // push eax
    "\x68\x2f\x2f\x73\x68"  // push "//sh"
    "\x68\x2f\x62\x69\x6e"  // push "/bin"
    "\x89\xe3"          // mov ebx, esp
    "\x50"              // push eax
    "\x53"              // push ebx
    "\x89\xe1"          // mov ecx, esp
    "\xb0\x0b"          // mov al, 11
    "\xcd\x80";         // int 0x80

int main() {
    printf("Shellcode bytes: ");
    for(int i=0; i<30; i++) {
        printf("\\x%02x", code[i]);
    }
    printf("\n");
    printf("Shellcode length: %lu bytes\n", strlen(code));
    return 0;
}
EOF

gcc -o shellcode_demo shellcode_demo.c
./shellcode_demo
```

**Key Concepts:**
- Shellcode is raw machine code
- Must avoid NULL bytes (0x00)
- Typically spawns a shell

---

## 10: Defense - Stack Canaries

### Key Points:
- **Canary**: Random value placed on stack
- **Location**: Between local variables and return address
- **Check**: Verified before function returns
- **Detection**: If changed, attack detected → program aborts

### Terminal Practice:
```bash
cat > canary.c << 'EOF'
#include <stdio.h>
#include <string.h>

void overflow(char *input) {
    char buffer[8];
    strcpy(buffer, input);
}

int main(int argc, char *argv[]) {
    if(argc > 1) overflow(argv[1]);
    printf("Success\n");
    return 0;
}
EOF

# Compile WITHOUT canary
gcc -o canary_off canary.c -fno-stack-protector
echo "Without protection:"
./canary_off $(python3 -c "print('A'*50)")

# Compile WITH canary (default)
gcc -o canary_on canary.c
echo -e "\nWith protection:"
./canary_on $(python3 -c "print('A'*50)")
```

**Expected Output:**
- Without: Segmentation fault
- With: "stack smashing detected"

---

## 11: Defense - Non-Executable Stack (NX)

### Key Points:
- **NX Bit**: Memory protection feature
- **Mark stack**: Non-executable (no code execution)
- **Prevention**: Shellcode on stack cannot execute
- **Hardware**: CPU enforces at memory management level

### Terminal Practice:
```bash
cat > nx_test.c << 'EOF'
#include <stdio.h>

int main() {
    printf("Testing NX protection\n");
    return 0;
}
EOF

# Compile with NX (default)
gcc -o nx_on nx_test.c -z noexecstack

# Compile without NX (dangerous)
gcc -o nx_off nx_test.c -z execstack

# Check protection
readelf -l nx_on | grep STACK
readelf -l nx_off | grep STACK
```

**Look for:**
- `RW` = Read-Write (NX enabled)
- `RWE` = Read-Write-Execute (NX disabled)

---

## 12: Defense - ASLR

### Key Points:
- **ASLR**: Address Space Layout Randomization
- **Randomizes**: Stack, heap, library addresses
- **Changes**: Every program execution
- **Difficulty**: Attacker can't predict addresses

### Terminal Practice:
```bash
cat > aslr.c << 'EOF'
#include <stdio.h>
int main() {
    int stack_var;
    printf("Stack: %p\n", &stack_var);
    printf("Main:  %p\n", main);
    return 0;
}
EOF

gcc -o aslr aslr.c

# Run multiple times
for i in 1 2 3 4 5; do
    echo "Run $i:"
    ./aslr
done

# Check ASLR status
cat /proc/sys/kernel/randomize_va_space
# 0=off, 1=conservative, 2=full
```

**Key Observation**: Addresses change each run

---

## 13: Defense - Guard Pages

### Key Points:
- **Guard pages**: Protected memory pages
- **Placed**: Between stack frames, around buffers
- **Marked**: Illegal access in MMU
- **Result**: Access triggers immediate abort

### Concept Diagram:
```
┌─────────────┐
│   Stack     │
├─────────────┤
│ GUARD PAGE  │ ← Illegal access
├─────────────┤
│   Heap      │
├─────────────┤
│ GUARD PAGE  │ ← Illegal access
├─────────────┤
│   Data      │
└─────────────┘
```

---

## 14: Compile-Time Defense - Safe Functions

### Key Points:
- **Replace unsafe**: Use bounded versions
- **Add checks**: Validate input length
- **Null terminate**: Always ensure strings terminated

### Terminal Practice:
```bash
cat > safe_code.c << 'EOF'
#include <stdio.h>
#include <string.h>

void unsafe_way() {
    char dest[10];
    char src[50] = "This is way too long";
    strcpy(dest, src);  // BAD!
}

void safe_way() {
    char dest[10];
    char src[50] = "This is way too long";
    
    // Use strncpy with size limit
    strncpy(dest, src, sizeof(dest)-1);
    dest[sizeof(dest)-1] = '\0';  // Ensure null termination
    
    printf("Safe result: %s\n", dest);
}

int main() {
    printf("=== Safe Coding Example ===\n");
    safe_way();
    // unsafe_way();  // Uncomment to crash
    return 0;
}
EOF

gcc -o safe_code safe_code.c
./safe_code
```

---

## 15: Input Validation

### Key Points:
- **Check length**: Before copying to buffer
- **Validate format**: Expected characters only
- **Sanitize input**: Remove dangerous characters
- **Error handling**: Reject invalid input

### Terminal Practice:
```bash
cat > validation.c << 'EOF'
#include <stdio.h>
#include <string.h>
#include <ctype.h>

int validate_input(const char *input, size_t max_len) {
    size_t len = strlen(input);
    
    // Check length
    if(len > max_len) {
        printf("❌ Too long! Max %lu chars\n", max_len);
        return 0;
    }
    
    // Check for alphanumeric only
    for(size_t i=0; i<len; i++) {
        if(!isalnum(input[i]) && input[i] != ' ') {
            printf("❌ Invalid character: %c\n", input[i]);
            return 0;
        }
    }
    
    printf("✓ Valid input\n");
    return 1;
}

int main() {
    validate_input("John123", 20);        // OK
    validate_input("Too long string here", 10);  // Fail
    validate_input("Bad<script>", 20);    // Fail
    return 0;
}
EOF

gcc -o validation validation.c
./validation
```

---

## 16: Static Analysis Tools

### Key Points:
- **Compiler warnings**: Enable all (-Wall -Wextra)
- **Static analyzers**: Scan code without running
- **Find bugs**: Before deployment
- **Tools**: gcc warnings, cppcheck, clang-analyzer

### Terminal Practice:
```bash
cat > buggy.c << 'EOF'
#include <stdio.h>
#include <string.h>

int main() {
    char buffer[10];
    char *input = "This is too long!";
    strcpy(buffer, input);  // Warning!
    printf(buffer);         // Warning!
    return 0;
}
EOF

# Compile with warnings
gcc -Wall -Wextra -Wformat-security buggy.c -o buggy

# Install and run cppcheck
# sudo apt-get install cppcheck
cppcheck --enable=all buggy.c
```

---

## 17: Dynamic Analysis - Valgrind

### Key Points:
- **Runtime checking**: Detects errors during execution
- **Memory leaks**: Finds unfreed memory
- **Buffer overruns**: Detects out-of-bounds access
- **Use with debug symbols**: Compile with -g

### Terminal Practice:
```bash
cat > memleak.c << 'EOF'
#include <stdlib.h>
#include <string.h>

int main() {
    char *buffer = malloc(10);
    strcpy(buffer, "Way too long string!");  // Overflow
    // Forgot to free(buffer)
    return 0;
}
EOF

gcc -g -o memleak memleak.c

# Install valgrind
# sudo apt-get install valgrind

valgrind --leak-check=full --show-leak-kinds=all ./memleak
```

**Key Output:**
- Invalid write detected
- Memory leak detected
- Stack traces show where

---

## 18: AddressSanitizer (ASan)

### Key Points:
- **Compiler feature**: GCC/Clang built-in
- **Fast detection**: Finds memory errors
- **Detailed reports**: Shows exact location
- **Compile flag**: -fsanitize=address

### Terminal Practice:
```bash
cat > asan_test.c << 'EOF'
#include <string.h>

int main() {
    char buffer[8];
    strcpy(buffer, "This overflows!");  // Error!
    return 0;
}
EOF

# Compile with AddressSanitizer
gcc -fsanitize=address -g -o asan_test asan_test.c
./asan_test
```

**Output Shows:**
- Exact overflow location
- Stack trace
- Memory address details

---

## 19: Real-World Example - Heartbleed

### Key Points:
- **Date**: April 2014
- **Vulnerability**: OpenSSL buffer over-read
- **Impact**: 500,000+ servers affected
- **Data leaked**: Passwords, private keys, session tokens
- **Cause**: Missing bounds check in heartbeat extension

### Simplified Concept:
```bash
cat > heartbleed_concept.c << 'EOF'
#include <stdio.h>
#include <string.h>

void vulnerable_heartbeat(char *data, int claimed_len) {
    char buffer[64];
    
    // No check if claimed_len > actual data!
    memcpy(buffer, data, claimed_len);  // VULNERABLE
    
    printf("Echo back: ");
    for(int i=0; i<claimed_len; i++) {
        printf("%c", buffer[i]);
    }
    printf("\n");
}

int main() {
    char actual_data[4] = "Hi!";
    
    printf("Normal request:\n");
    vulnerable_heartbeat(actual_data, 3);
    
    printf("\nMalicious request (claim 20 bytes):\n");
    vulnerable_heartbeat(actual_data, 20);  // Reads beyond!
    
    return 0;
}
EOF

gcc -o heartbleed_concept heartbleed_concept.c
./heartbleed_concept
```

---

## 20: Format String Vulnerability

### Key Points:
- **Mistake**: Using user input as format string
- **Dangerous**: `printf(user_input)` instead of `printf("%s", user_input)`
- **Exploit**: Read/write arbitrary memory
- **Format specifiers**: %x, %n can leak/modify memory

### Terminal Practice:
```bash
cat > format_string.c << 'EOF'
#include <stdio.h>

int main(int argc, char *argv[]) {
    int secret = 0xDEADBEEF;
    
    if(argc < 2) {
        printf("Usage: %s <input>\n", argv[0]);
        return 1;
    }
    
    printf("Secret at: %p = 0x%x\n\n", &secret, secret);
    
    printf("WRONG way:\n");
    printf(argv[1]);  // VULNERABLE!
    
    printf("\n\nRIGHT way:\n");
    printf("%s", argv[1]);  // SAFE
    
    printf("\n");
    return 0;
}
EOF

gcc -o format_string format_string.c

# Normal input
./format_string "Hello"

# Leak stack data
./format_string "%x.%x.%x.%x"

# Leak addresses
./format_string "%p.%p.%p.%p"
```

**What Happened?**
- `%x` reads data from stack
- Can leak sensitive information
- `%n` can even write to memory!

---

## 21: Heap Overflow

### Key Points:
- **Location**: Overflow in heap-allocated buffer
- **Target**: Adjacent heap objects
- **Danger**: Overwrite function pointers, object data
- **Different from stack**: No return address, but other exploits

### Terminal Practice:
```bash
cat > heap_overflow.c << 'EOF'
#include <stdio.h>
#include <stdlib.h>
#include <string.h>

typedef struct {
    char name[16];
    void (*func)();
} User;

void normal() { printf("Normal function\n"); }
void admin() { printf("🚨 Admin function!\n"); }

int main(int argc, char *argv[]) {
    User *user = malloc(sizeof(User));
    user->func = normal;
    
    printf("User at: %p\n", user);
    printf("Name at: %p\n", user->name);
    printf("Func at: %p\n", &user->func);
    
    if(argc > 1) {
        strcpy(user->name, argv[1]);  // OVERFLOW!
    }
    
    printf("Calling function...\n");
    user->func();
    
    free(user);
    return 0;
}
EOF

gcc -o heap_overflow heap_overflow.c

./heap_overflow "Bob"              # Normal
./heap_overflow $(python3 -c "print('A'*30)")  # Overflow
```

---

## 22: Return-Oriented Programming (ROP)

### Key Points:
- **Technique**: Chain existing code fragments ("gadgets")
- **Bypass**: NX protection (no shellcode needed)
- **Method**: Overwrite stack with gadget addresses
- **Advanced**: Requires deep understanding

### Concept:
```
Instead of injecting shellcode:
┌──────────────┐
│  Your Code   │  ← Blocked by NX
└──────────────┘

Use existing code:
┌──────────────┐
│ Gadget 1     │  ← "pop rdi; ret"
├──────────────┤
│ Gadget 2     │  ← "mov rax, rdi; ret"
├──────────────┤
│ Gadget 3     │  ← "syscall; ret"
└──────────────┘
```

---

## 23: Fuzzing

### Key Points:
- **Fuzzing**: Automated testing with random/malformed input
- **Goal**: Find crashes and vulnerabilities
- **Tools**: AFL, LibFuzzer, Radamsa
- **Effective**: Discovers unknown bugs

### Terminal Practice:
```bash
cat > fuzz_target.c << 'EOF'
#include <stdio.h>
#include <string.h>

void process_input(char *input) {
    char buffer[16];
    
    if(strlen(input) > 10) {
        strcpy(buffer, input);  // Potential overflow
    } else {
        strncpy(buffer, input, 15);
        buffer[15] = '\0';
    }
}

int main(int argc, char *argv[]) {
    if(argc > 1) {
        process_input(argv[1]);
        printf("Processed OK\n");
    }
    return 0;
}
EOF

gcc -o fuzz_target fuzz_target.c

# Manual fuzzing
for len in 5 10 15 20 50 100; do
    echo "Testing length $len"
    ./fuzz_target $(python3 -c "print('A'*$len)")
done
```

---

## 24: Secure Development Lifecycle

### Key Points:
- **Design phase**: Security requirements
- **Development**: Secure coding standards
- **Testing**: Security testing, code review
- **Deployment**: Hardened configuration
- **Maintenance**: Security updates, monitoring

### Checklist:
```
☐ Use safe functions (strncpy, snprintf)
☐ Validate all input
☐ Enable compiler warnings
☐ Use static analysis tools
☐ Enable stack protections
☐ Test with fuzzing
☐ Code review by peers
☐ Keep dependencies updated
```

---

## 25: Best Practices Summary

### Prevention Strategies:

**1. Language Choice:**
- Use memory-safe languages when possible (Rust, Go, Python)
- If C/C++ required, use modern standards (C11, C++17)

**2. Coding Practices:**
```bash
cat > best_practices.c << 'EOF'
#include <stdio.h>
#include <string.h>

#define MAX_INPUT 100

int main() {
    char buffer[MAX_INPUT];
    
    // ✓ GOOD: Use fgets with size limit
    printf("Enter name: ");
    if(fgets(buffer, sizeof(buffer), stdin)) {
        buffer[strcspn(buffer, "\n")] = 0;  // Remove newline
    }
    
    // ✓ GOOD: Use snprintf
    char output[50];
    snprintf(output, sizeof(output), "Hello, %s!", buffer);
    
    // ✓ GOOD: Always check return values
    FILE *f = fopen("test.txt", "r");
    if(f == NULL) {
        perror("Failed to open file");
        return 1;
    }
    fclose(f);
    
    return 0;
}
EOF

gcc -Wall -Wextra -o best_practices best_practices.c
./best_practices
```

**3. Compilation Flags:**
```bash
# Always use these flags
gcc -Wall -Wextra \
    -Wformat-security \
    -D_FORTIFY_SOURCE=2 \
    -fstack-protector-strong \
    -fPIE -pie \
    -o secure_program program.c
```

**4. Regular Auditing:**
- Code reviews
- Automated scanning
- Penetration testing
- Security updates

---

## Quick Reference Card

### Unsafe → Safe Function Mapping:
```
gets()          → fgets(buf, size, stdin)
strcpy()        → strncpy() + null terminate
strcat()        → strncat()
sprintf()       → snprintf()
scanf("%s")     → scanf("%20s") or fgets()
```

### GCC Security Flags:
```bash
-fstack-protector-strong  # Stack canaries
-D_FORTIFY_SOURCE=2       # Buffer overflow checks
-fPIE -pie                # Position independent
-Wformat-security         # Format string warnings
```

### Check Protections:
```bash
readelf -l program | grep STACK    # NX bit
checksec --file=program            # All protections
```

---

## Final Lab: Complete Secure Program

```bash
cat > secure_login.c << 'EOF'
#include <stdio.h>
#include <string.h>
#include <ctype.h>

#define MAX_USER 32
#define MAX_PASS 64

int validate_username(const char *user) {
    size_t len = strlen(user);
    if(len == 0 || len >= MAX_USER) return 0;
    
    for(size_t i=0; i<len; i++) {
        if(!isalnum(user[i]) && user[i] != '_') {
            return 0;
        }
    }
    return 1;
}

int main() {
    char username[MAX_USER];
    char password[MAX_PASS];
    
    printf("=== Secure Login System ===\n");
    
    // Safe input reading
    printf("Username: ");
    if(!fgets(username, sizeof(username), stdin)) {
        return 1;
    }
    username[strcspn(username, "\n")] = 0;
    
    // Validation
    if(!validate_username(username)) {
        fprintf(stderr, "Invalid username format\n");
        return 1;
    }
    
    printf("Password: ");
    if(!fgets(password, sizeof(password), stdin)) {
        return 1;
    }
    password[strcspn(password, "\n")] = 0;
    
    // Safe comparison
    if(strncmp(username, "admin", MAX_USER) == 0 &&
       strncmp(password, "secure123", MAX_PASS) == 0) {
        printf("✓ Login successful\n");
    } else {
        printf("✗ Login failed\n");
    }
    
    // Clear sensitive data
    memset(password, 0, sizeof(password));
    
    return 0;
}
EOF

gcc -Wall -Wextra -fstack-protector-strong -D_FORTIFY_SOURCE=2 \
    -o secure_login secure_login.c
./secure_login
```

---
