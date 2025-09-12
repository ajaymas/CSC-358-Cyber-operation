# Hands-on Linux exercises — one working example for each access-control model (RBAC, ABAC, DAC, MAC)

> Run these in a **disposable Linux VM** (Ubuntu/CentOS) with `sudo` privileges. These are teaching demos — they modify users, groups, files and attributes. Do **not** run on a production host.

This document provides **step‑by‑step commands**, short explanations for each command, how to test the behavior, and cleanup steps for each access-control model.

---

## Prerequisites

- A disposable VM (VirtualBox/LXC/Docker VM) you are free to modify.
- `sudo` access in that VM.
- Install helper packages if missing (Debian/Ubuntu example):

```bash
sudo apt update
sudo apt install -y attr acl
“To access root mode in the Remnux VM, use the following command as an example:”
remnux@remnux:~$ sudo su -
```

- Notes:
  - `attr` provides `setfattr`/`getfattr` for extended attributes.
  - `acl` provides `setfacl`/`getfacl` for Access Control Lists (used in DAC example).

---

# 1) RBAC — simulate roles with Unix groups (Hospital example)

**Goal:** doctors can read/write `/hospital/records.txt`, nurses & receptionists cannot.

### Commands & explanation

```bash
# 1. create groups (roles)
sudo groupadd doctors
sudo groupadd nurses
sudo groupadd receptionists
```
*`groupadd` creates Unix groups which we will use as roles.*

```bash
# 2. create users and put them in groups
sudo useradd -m -s /bin/bash alice        # doctor (will add to doctors)
sudo usermod -aG doctors alice

sudo useradd -m -s /bin/bash bob          # nurse
sudo usermod -aG nurses bob

sudo useradd -m -s /bin/bash charlie      # receptionist
sudo usermod -aG receptionists charlie
```
*`useradd -m` creates a home directory; `usermod -aG` appends group membership.*

```bash
# 3. make resource directory & file, set ownership and permissions
sudo mkdir -p /hospital
sudo touch /hospital/records.txt
sudo chown root:doctors /hospital/records.txt
sudo chmod 0640 /hospital/records.txt
echo "Patient A: blood type O+" | sudo tee /hospital/records.txt >/dev/null
```
- `chown root:doctors` makes the group owner `doctors`.
- `chmod 0640` = owner `rw-`, group `r--`, others `---`. That means anyone in `doctors` can read; only root can write.

```bash
# 4. allow doctors group to write too (optional)
sudo chmod 0660 /hospital/records.txt
```
- `0660` = owner `rw`, group `rw`, others `none`.

### Test as the different users

```bash
# as Alice (doctor) – should read & (if 0660) write
sudo -u alice cat /hospital/records.txt
sudo -u alice sh -c 'echo "Doctor note by Alice" >> /hospital/records.txt'   # append

# as Bob (nurse) – should get "Permission denied"
sudo -u bob cat /hospital/records.txt || echo "bob could not read (expected)"

# as Charlie (receptionist) – should be denied
sudo -u charlie cat /hospital/records.txt || echo "charlie could not read (expected)"
```
- `sudo -u user cmd` runs `cmd` as that user. When using redirection (`>>`) inside `sudo -u`, wrap with `sh -c` so the redirection happens in the target user’s shell.

### Verify permissions & ownership

```bash
ls -l /hospital/records.txt
getent group doctors   # show members of doctors group
```

### Cleanup (when done)

```bash
sudo rm -rf /hospital
sudo userdel -r alice
sudo userdel -r bob
sudo userdel -r charlie
sudo groupdel doctors nurses receptionists
```

---

# 2) ABAC — attributes of user/resource/environment (Cloud storage example)

Linux doesn’t have a built-in ABAC engine; we **simulate** ABAC using extended file attributes (`setfattr`/`getfattr`) for resource attributes, a small user-attribute mapping file, and a script that enforces a policy based on the user attributes + resource attributes + current environment (office hours).

> If `setfattr/getfattr` are missing: `sudo apt install attr`.

### Setup

```bash
# 1. create users (professor & student)
sudo useradd -m -s /bin/bash professor1
sudo useradd -m -s /bin/bash student1

# 2. create a resource file (simulate cloud doc)
sudo mkdir -p /srv/cloud
echo "Confidential research notes" | sudo tee /srv/cloud/research.txt >/dev/null
sudo chown root:root /srv/cloud/research.txt

# 3. set a resource attribute: classification = confidential
sudo setfattr -n user.classification -v "confidential" /srv/cloud/research.txt

# 4. create a simple user-attribute mapping (admin only)
sudo tee /etc/abac_user_attrs >/dev/null <<'EOF'
professor1:role=professor;affiliation=university
student1:role=student;affiliation=university
EOF
sudo chmod 644 /etc/abac_user_attrs
```
- `setfattr` attaches an extended attribute `user.classification` to the file.
- `/etc/abac_user_attrs` is a simple text lookup for this demo. In real systems you’d query LDAP/IdP.

### ABAC enforcement script

Create a small script that reads user attributes, resource attributes, and the environment (current hour) and then enforces a sample policy.

```bash
sudo tee /usr/local/bin/abac_check.sh >/dev/null <<'EOF'
#!/bin/bash
# usage: abac_check.sh <username> <resource>
user="$1"
resource="$2"

# read user attributes from /etc/abac_user_attrs
ua=$(grep "^${user}:" /etc/abac_user_attrs 2>/dev/null | cut -d: -f2)
role=$(echo "$ua" | sed -n 's/.*role=\([^;]*\).*/\1/p')
# get resource attribute (classification)
class=$(getfattr --only-values -n user.classification "$resource" 2>/dev/null || echo "none")

# environment: allow access only during office hours 09..17 UNLESS ABAC_TEST_HOUR is set
HOUR=${ABAC_TEST_HOUR:-$(date +%H)}

echo "DEBUG: user=$user role=$role resource=$resource class=$class hour=$HOUR"

# sample policy:
# professors can read confidential resources during office hours (09-17)
if [ "$role" = "professor" ] && [ "$class" = "confidential" ] && [ "$HOUR" -ge 9 ] && [ "$HOUR" -lt 17 ]; then
  echo "ACCESS GRANTED: showing file..."
  cat "$resource"
  exit 0
else
  echo "ACCESS DENIED by ABAC policy"
  exit 1
fi
EOF

sudo chmod 755 /usr/local/bin/abac_check.sh
```

- The script extracts `role` from `/etc/abac_user_attrs`, reads resource `classification` with `getfattr`, reads current hour and makes a policy decision.
- `ABAC_TEST_HOUR` environment variable lets you override the current hour for testing.

### Test ABAC

```bash
# Test as professor during "office hours" by forcing test hour to 10:
sudo ABAC_TEST_HOUR=10 /usr/local/bin/abac_check.sh professor1 /srv/cloud/research.txt

# Test as student (should be denied)
sudo ABAC_TEST_HOUR=10 /usr/local/bin/abac_check.sh student1 /srv/cloud/research.txt

# Show resource attribute
getfattr -n user.classification /srv/cloud/research.txt
```

### Explanation

- **User attributes:** stored in `/etc/abac_user_attrs` (role, affiliation). In production these are typically fetched from an identity/source of truth.
- **Resource attributes:** `user.classification` set using `setfattr`.
- **Environment:** current hour (other examples: network location, device posture, MFA status).
- **Policy:** dynamic decision combining all three axes.

### Cleanup

```bash
sudo rm -f /usr/local/bin/abac_check.sh
sudo rm -rf /srv/cloud
sudo rm -f /etc/abac_user_attrs
sudo userdel -r professor1 student1
```

---

# 3) DAC — owner-controlled permissions and ACLs (Project doc example)

**Goal:** A document owned by a project manager (`pm`) where the owner grants `rw` to `team_member` and `r` to `intern` using ACLs.

### Commands & explanation

```bash
# 1. create users
sudo useradd -m -s /bin/bash pm
sudo useradd -m -s /bin/bash team_member
sudo useradd -m -s /bin/bash intern

# 2. create project file and set pm as owner
sudo mkdir -p /project
sudo touch /project/plan.doc
sudo chown pm:pm /project/plan.doc
sudo chmod 0640 /project/plan.doc
echo "Project plan v1" | sudo tee /project/plan.doc >/dev/null
```
- Default Unix DAC: owner `pm` controls the file's basic permissions.

```bash
# 3. pm grants fine-grained access to specific users using ACLs (setfacl)
sudo setfacl -m u:team_member:rw /project/plan.doc
sudo setfacl -m u:intern:r /project/plan.doc

# view ACLs
getfacl /project/plan.doc
```
- `setfacl -m` modifies ACLs; `getfacl` shows them. This is classic DAC: the resource owner decides authorizations.

### Test

```bash
# team_member reads & writes (append)
sudo -u team_member sh -c 'cat /project/plan.doc'
sudo -u team_member sh -c 'echo "Added by team_member" >> /project/plan.doc'

# intern reads only (write should fail)
sudo -u intern sh -c 'cat /project/plan.doc'
sudo -u intern sh -c 'echo "I intern edit" >> /project/plan.doc' || echo "intern write denied (expected)"

# non-authorized user should be denied
sudo useradd -m outsider
sudo -u outsider sh -c 'cat /project/plan.doc' || echo "outsider denied (expected)"
```

### Notes

- ACLs are discretionary: the owner (or admin) sets them. ACLs can be changed/removed by the owner or a privileged user.
- To remove an ACL entry: `sudo setfacl -x u:team_member /project/plan.doc`.

### Cleanup

```bash
sudo rm -rf /project
sudo userdel -r pm team_member intern outsider
```

---

# 4) MAC — labels vs clearances (simulated) — “Top Secret” example

Linux kernel provides MAC via LSMs (SELinux, AppArmor). Full SELinux policy authoring is advanced. Below are two parts:

A. A **user-space simulation** that demonstrates MAC semantics (labels assigned by admin, clearances assigned by admin, strict comparison performed by an enforcement script). This is a teaching demo.

B. Quick commands to explore **real kernel MAC** (SELinux/AppArmor) if your distro supports it.

---

## A — Simulated MAC via labels + enforcement script

**Idea:** Files receive a `security.label` xattr (e.g., `TopSecret`, `Secret`, `Confidential`). A clearance map `/etc/clearances` maps users to clearances. Only users with clearance >= file label can access. Only admin can change `security.label`.

### Setup

```bash
# create users
sudo useradd -m -s /bin/bash alice   # will be TopSecret clearance
sudo useradd -m -s /bin/bash bob     # Secret clearance

# create clearance map (admin only)
sudo tee /etc/clearances >/dev/null <<'EOF'
alice:TopSecret
bob:Secret
EOF
sudo chmod 644 /etc/clearances

# create files and attach labels (xattrs)
sudo mkdir -p /secure
echo "Top Secret intel" | sudo tee /secure/topsecret.txt >/dev/null
echo "Secret memo" | sudo tee /secure/secret.txt >/dev/null

sudo setfattr -n security.label -v "TopSecret" /secure/topsecret.txt
sudo setfattr -n security.label -v "Secret" /secure/secret.txt
```

### Enforcement script (admin-only)

```bash
sudo tee /usr/local/bin/mac_enforce.sh >/dev/null <<'EOF'
#!/bin/bash
# usage: mac_enforce.sh <username> <resource>
user="$1"
resource="$2"

# read clearance
clearance=$(grep "^${user}:" /etc/clearances 2>/dev/null | cut -d: -f2)
[ -z "$clearance" ] && { echo "No clearance for $user"; exit 2; }

# read file label
label=$(getfattr --only-values -n security.label "$resource" 2>/dev/null || echo "Unclassified")

echo "DEBUG: user=$user clearance=$clearance file=$resource label=$label"

# numeric ranking for comparison
rank() {
  case "$1" in
    Unclassified) echo 0;;
    Confidential) echo 1;;
    Secret) echo 2;;
    TopSecret) echo 3;;
    *) echo 0;;
  esac
}

if [ $(rank "$clearance") -ge $(rank "$label") ]; then
  echo "ACCESS GRANTED (mac)"
  cat "$resource"
  exit 0
else
  echo "ACCESS DENIED (mac): clearance too low"
  exit 1
fi
EOF

sudo chmod 755 /usr/local/bin/mac_enforce.sh
```

### Test

```bash
# Alice (TopSecret) reads both files
sudo /usr/local/bin/mac_enforce.sh alice /secure/topsecret.txt
sudo /usr/local/bin/mac_enforce.sh alice /secure/secret.txt

# Bob (Secret) reads Secret but not TopSecret
sudo /usr/local/bin/mac_enforce.sh bob /secure/secret.txt
sudo /usr/local/bin/mac_enforce.sh bob /secure/topsecret.txt || echo "bob denied (expected)"
```

### Explanation

- `security.label` is set by the admin (using `setfattr`). Users should not be able to change labels in this model.
- Enforcement compares numeric ranks of clearance vs label. If clearance < label, access denied.
- This **simulates** MAC semantics in userland. Real MAC is kernel-enforced (SELinux/AppArmor) and cannot be bypassed by ordinary users.

### Cleanup (simulated MAC)

```bash
sudo rm -rf /secure
sudo rm -f /usr/local/bin/mac_enforce.sh
sudo rm -f /etc/clearances
sudo userdel -r alice bob
```

---

## B — Quick check for real kernel MAC (SELinux / AppArmor)

If your Linux distro supports SELinux or AppArmor you can quickly explore real MAC enforcement:

**SELinux**

```bash
# check status (RHEL/CentOS/Ubuntu with SELinux)
sestatus        # or: getenforce

# view security context of a file
ls -Z /etc/hosts

# change a file's SELinux type (temporary)
sudo chcon -t httpd_sys_content_t /var/www/html/index.html
ls -Z /var/www/html/index.html
```

- `sestatus` shows whether SELinux is enabled/enforcing. `chcon` changes file SELinux context; the process’s SELinux domain and policy decide access.

**AppArmor (Ubuntu)**

```bash
# check AppArmor status
sudo apparmor_status

# see profiles & deny messages
sudo aa-status
```

> Real MAC enforcement performed by kernel LSMs is stronger than the user-space simulations above and typically requires policy authoring and admin-level configuration.

---

# Final notes & tips

- **Always run these demos in a disposable VM** (VirtualBox, Vagrant, LXD, or a throwaway cloud instance). These commands create/delete Linux users and groups.
- Install helper packages if missing: `sudo apt install -y attr acl` (Debian/Ubuntu) or the equivalent for your distribution.
- The **ABAC and MAC scripts** here are teaching demos. In production:
  - ABAC is often implemented with policy engines like **OPA**, **XACML** or an identity provider (IdP).
  - MAC is enforced by kernel LSMs such as **SELinux** and **AppArmor**.
---
*End of document.*

