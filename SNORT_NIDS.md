
# Network Intrusion Detection System (Snort) — Practical Guide

## Overview
Snort is an open-source network intrusion detection and prevention system (IDS/IPS). It can monitor, detect, and optionally block malicious traffic using customizable rules.

---

## Installation and Setup

### 1. Install Dependencies and Snort
```bash
sudo apt update
sudo apt install -y build-essential libpcap-dev libpcre3-dev      libdnet-dev zlib1g-dev openssl libssl-dev pkg-config      libdumbnet-dev bison flex
sudo apt install snort
```

For Snort 3 (Docker option):
```bash
sudo docker pull ciscotalos/snort3
sudo docker run --name snort3 -d -it ciscotalos/snort3 bash
sudo docker exec -it snort3 bash
```

### 2. Verify Installation
```bash
snort --version
```

---

## Configuration and Validation

### 3. Test Configuration
```bash
snort -T -c /etc/snort/snort.conf
```

### 4. Run Snort Modes
| Mode | Command | Description |
|------|----------|-------------|
| Daemon | `snort -c /etc/snort/snort.conf -D` | Run in background |
| Console alerts | `snort -c /etc/snort/snort.conf -v -A console` | Show alerts live |
| File logging | `snort -c /etc/snort/snort.conf -v -A fast` | Log alerts in file |
| No logging | `snort -c /etc/snort/snort.conf -N` | Disable logging |

---

## Traffic Capture and Filtering

### 5. Sniff Live or PCAP Traffic
```bash
snort -c /etc/snort/snort.conf -i eth0
snort -r example.pcap -c /etc/snort/snort.conf
snort -b -L packets.pcap
snort -q -A console -c /etc/snort/snort.conf host 10.1.1.33
```

---

## Custom Rules

### 6. Add and Test Rules
Edit `/etc/snort/rules/local.rules`:
```
alert icmp any any -> any any (msg:"ICMP connection attempt"; sid:1000010; rev:1;)
```

Run Snort to test:
```bash
snort -q -A console -c /etc/snort/snort.conf
```

Trigger by sending ping traffic.

### 7. Inline IPS Mode Rules
```
reject icmp any any -> $HOME_NET any (msg:"ICMP blocked"; sid:1000011; rev:1;)
```

---

## Enable Rule Sets

Edit `snort.conf` and uncomment needed rules:
```
include $RULE_PATH/app-detect.rules
include $RULE_PATH/malware-backdoor.rules
```

Then test:
```bash
snort -T -c /etc/snort/snort.conf
```

---

## Log and Alert Review

View alerts/logs:
```bash
cd /var/log/snort/
tail -f alert
```

---

## Workflow Summary

1. Install Snort and dependencies  
2. Verify installation  
3. Configure and test snort.conf  
4. Enable rule sets  
5. Add local rules  
6. Test and validate configuration  
7. Run Snort (console, daemon, or inline)  
8. Generate traffic and verify alerts  
9. Monitor logs and fine-tune rules

---
