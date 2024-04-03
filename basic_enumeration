#!/bin/bash

echo "Gathering User Context Information" > audit
id >> audit
echo "Consider reading the /etc/passwd file"  >> audit
echo "" >> audit
echo "Checking hostname" >> audit
hostname >> audit
echo "" >> audit
echo "Gathering information about the OS version" >> audit
cat /etc/issue >> audit
echo "" >> audit
echo "Gathering release specific information" >> audit
cat /etc/os-release > os-release >> audit
echo "" >> audit
echo "Checking kernel version and architecture" >> audit
uname -a >> audit
echo "" >> audit
echo "Checking for processes that run in the context of a privileged account and have insecure permissions or allow us to interact with it in unintended ways." >> audit
echo "Listing system processes, including those run by privileged users." >> audit
ps aux >> audit
echo "" >> audit
echo "Checking for virtual interfaces and port bindings, including services running locally" >> audit
ip a >> audit
echo "" >> audit
echo "Display network routing tables" >> audit
routel >> audit
echo "" >> audit
echo "Displaying active network connections and listening ports" >> audit
ss -anp >> audit
netstat -anp >> audit
echo "" >> audit
echo "Listing firewall rules" >> audit
cat /etc/iptables >> audit
cat /etc/iptables/rules.v4 >> audit
echo "" >> audit
echo "Checking scheduled tasks. Make sure to check for weak permissions." >> audit
ls -lah /etc/cron* >> audit
echo "" >> audit
echo "Viewing the current user's scheduled jobs." >> audit
crontab -l >> audit
echo "Viewing the sudo user's scheduled jobs." >> audit
sudo crontab -l >> audit
echo "" >> audit
echo "Manually querying installed packages." >> audit
echo "Listing applications installed by dpkg" >> audit
dpkg -l >> audit
echo "" >> audit
echo "Checking for directories with insecure permissions (every directory writable by the current user on the target system)" >> audit
find / -writable -type d 2>/dev/null >> audit
echo "" >> audit
echo "Checking for files with insecure permissions (every file wreitable by the current user on the target system)." >> audit
find / -writable -type f 2>/dev/null >> audit
echo "" >> audit
echo "Checking for drives that will be mounted at boot time." >> audit
cat /etc/fstab >> audit
echo "" >> audit
echo "Checking for available disks." >> audit
lsblk >> audit
echo "" >> audit
echo "Gathering a list of drivers and kernel modules that are loaded on a target" >> audit
lsmod >> audit
echo "" >> audit
echo "Finding out more info about the specific module." >> audit
/sbin/modinfo libata >> audit
echo "" >> audit
echo "Checking for SUID and SGID on files (symbolized by letter s)" >> audit
echo "If a binary has the SUID bit set and the file is owned by root, any local user will be able to execute that binary with elevated privileges" >> audit
echo "eUID and eGID are the ID of the actual user that executes the program. That's how a normal user executes in the context of root" >> audit
echo "Checking for suid marked binaries" >> audit
find / -perm -u=s -type -f 2>/dev/null > find >> audit
