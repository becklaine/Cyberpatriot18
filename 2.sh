#!/bin/bash
echo Updating
apt-get update -y
apt-get upgrade -y

echo Enabling UFW
ufw enable
ufw default deny incoming
ufw default allow outgoing

echo Stopping bad cookies
sysctl -n net.ipv4.tcp_syncookies

echo Upgrading Systemd
apt upgrade systemd

echo Making sure only default account can sudo
visudo

echo Installing libpam-cracklib
apt-get install libpam-cracklib

echo Removing hacker tools
apt purge wireshark* ophcrack* john* deluge* nmap* hydra*

echo Enabling Automatic Updates (Daily)
apt install unattended-upgrades
