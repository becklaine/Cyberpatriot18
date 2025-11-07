#!/usr/bin/env bash
#First iteration of the Linux CyberPatriot Bash Script! (Made by Chatgpt)
# Script to automate the “Basics” checklist (excluding chmod commands)
# Usage: run as root (or via sudo)
set -euo pipefail

echo "=== Starting basics checklist automation ==="

# 1. Update package lists & upgrade system
echo "--> Updating package lists"
apt-get update -y
echo "--> Upgrading installed packages"
apt-get upgrade -y

# 2. Remove unnecessary packages/tools (e.g., “hacking tools”)
# NOTE: adjust list to your environment and what is considered unnecessary.
UNWANTED_PACKAGES=(
  john
  hydra
  hashcat
  netcat
  nmap
)
for pkg in "${UNWANTED_PACKAGES[@]}"; do
  if dpkg-query -W-f='${Status}' "$pkg" 2>/dev/null | grep -q "install ok installed"; then
    echo "--> Purging unwanted package: $pkg"
    apt-get purge -y "$pkg"
  else
    echo "--> Package $pkg not installed — skipping"
  fi
done
echo "--> Autoremoving leftover dependencies"
apt-get autoremove -y

# 3. Secure root login: disable direct root SSH login
SSH_CFG="/etc/ssh/sshd_config"
if grep -q "^PermitRootLogin" "$SSH_CFG"; then
  sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' "$SSH_CFG"
else
  echo "PermitRootLogin no" >> "$SSH_CFG"
fi
echo "--> Restarting sshd"
systemctl restart sshd

# 4. Disable guest login (for Ubuntu / lightdm)
if [ -f /etc/lightdm/lightdm.conf ]; then
  if grep -q "^allow-guest" /etc/lightdm/lightdm.conf; then
    sed -i 's/^allow-guest.*/allow-guest=false/' /etc/lightdm/lightdm.conf
  else
    echo "allow-guest=false" >> /etc/lightdm/lightdm.conf
  fi
  echo "--> Restarting display manager"
  systemctl restart lightdm
else
  echo "--> lightdm not in use (or file not found) — skipping guest disable"
fi

# 5. Check users with uid 0 or login permissions, remove unauthorized
echo "--> Checking for users with UID 0"
awk -F: '($3==0){print $1}' /etc/passwd | while read u; do
  if [ "$u" != "root" ]; then
    echo "----> Found extra UID0 user: $u — consider deleting"
    # userdel -r "$u"     # Commented out: manual verification recommended
  fi
done

echo "--> Checking sudoers for non-sudo group members"
# List members of sudo/admin according to your distro; example for Debian/Ubuntu:
getent group sudo | awk -F: '{print $4}' | tr ',' '\n' | \
  while read mem; do
    if [ -n "$mem" ]; then
      echo "----> sudo group member: $mem — verify if authorized"
      # To remove: gpasswd -d "$mem" sudo
    fi
done

# 6. Enforce password requirements (minimum length, history, complexity, lockout)
echo "--> Configuring /etc/login.defs"
sed -i 's/^PASS_MIN_DAYS.*/PASS_MIN_DAYS   7/' /etc/login.defs
sed -i 's/^PASS_MAX_DAYS.*/PASS_MAX_DAYS   90/' /etc/login.defs
sed -i 's/^PASS_WARN_AGE.*/PASS_WARN_AGE   14/' /etc/login.defs

echo "--> Configuring PAM password complexity and history"
PAM_PW="/etc/pam.d/common-password"
if grep -q "pam_unix.so" "$PAM_PW"; then
  sed -i 's/pam_unix.so/& minlen=8 remember=5 ucredit=-1 lcredit=-1 dcredit=-1 ocredit=-1/' "$PAM_PW"
else
  echo "Password complexity rules not found in $PAM_PW — manual review needed"
fi

echo "--> Configuring account lockout"
PAM_AUTH="/etc/pam.d/common-auth"
if grep -q "pam_tally2.so" "$PAM_AUTH"; then
  sed -i 's/pam_tally2.so/& deny=5 unlock_time=1800/' "$PAM_AUTH"
else
  echo "Lockout rule not found in $PAM_AUTH — manual review needed"
fi

# 7. Enable firewall (ufw) & disable IPv6, IP forwarding, etc
echo "--> Enabling UFW firewall"
ufw enable
echo "--> Setting firewall default rules"
ufw default deny incoming
ufw default allow outgoing

echo "--> Disabling IPv6"
grep -q "disable_ipv6 = 1" /etc/sysctl.conf || echo "net.ipv6.conf.all.disable_ipv6 = 1" >> /etc/sysctl.conf

echo "--> Disabling IP forwarding"
grep -q "net.ipv4.ip_forward = 0" /etc/sysctl.conf || echo "net.ipv4.ip_forward = 0" >> /etc/sysctl.conf

echo "--> Preventing IP spoofing"
grep -q "nospoof on" /etc/host.conf || echo "nospoof on" >> /etc/host.conf

echo "--> Applying sysctl changes"
sysctl -p

# 8. Check open ports, identify ones that should be closed
echo "--> Listing listening ports"
ss -lnptu

# Here you might script logic to close specific ports, but automation is risky — manual review recommended.

# 9. Update kernel and services to latest versions
echo "--> Installing latest kernel (if available via distro)"
apt-get dist-upgrade -y

# For specific services you must manually check each service version and upgrade.
echo "--> Manual: check major services version and upgrade as needed"

# 10. Service configuration review: list all services, ensure legitimate
echo "--> Listing all active services"
systemctl list-units --type=service --state=running

