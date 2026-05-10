#!/bin/bash

# Enhanced Privilege Escalation and Enumeration Script

echo "Starting Enhanced Privilege Escalation and Enumeration Checks..."

# Define directories for cron job enumeration
cron_dirs=(/etc/cron.d /etc/cron.daily /etc/cron.hourly /etc/cron.monthly /etc/cron.weekly /etc/cron.yearly)

# Check if current user is in Docker group
check_docker_group() {
    echo "[*] Checking if current user is in Docker group..."
    if id | grep -q docker; then
        echo "Current user is part of Docker group."
    else
        echo "Current user is not part of Docker group."
    fi
}

# Function to enumerate cron jobs, at jobs, and writable files
enumerate_cron_and_at_jobs() {
    echo "[*] Enumerating Cron Jobs, AT Jobs, and Checking for Writable Cron Files..."
    for dir in "${cron_dirs[@]}"; do
        echo "Inspecting $dir..."
        find "$dir" -type f ! -name "*.placeholder" -exec ls -la {} \;
    done
    echo "Listing all /etc/cron files:"
    ls -l /etc/cron* 2>/dev/null
    echo "Enumerating AT jobs..."
    atq || echo "No AT jobs found or not permitted to view."
    echo "Checking current user's scheduled jobs with crontab..."
    crontab -l
}

# Function to identify SUID binaries
identify_suid_binaries() {
    echo "[*] Identifying SUID Binaries..."
    find / -perm -4000 -type f 2>/dev/null
}

# Function to check for world-writable files, expanded to include more directories and executable files
check_world_writable_files() {
    echo "[*] Checking for World-Writable Files across the filesystem..."
    find / -type f -perm -2 ! -path "/proc/*" ! -path "/sys/*" 2>/dev/null
    echo "[*] Checking for World-Writable Directories..."
    find / -type d -writable 2>/dev/null
}

# Function to review running processes
review_processes() {
    echo "[*] Reviewing Running Processes..."
    ps aux
}

# Function to search for plaintext passwords and sensitive files
search_plaintext_passwords_and_sensitive_files() {
    echo "[*] Searching for Plaintext Passwords and Sensitive Files..."
    find / -type f \( -name "*.conf" -o -name "*.cfg" -o -name "*.txt" \) -exec grep -Hi "password" {} \; 2>/dev/null
}

# Network and system information including kernel version
network_system_info_and_kernel_version() {
    echo "[*] Gathering Network, System Information, and Kernel Version..."
    ifconfig || ip a
    netstat -tuln || ss -tuln
    hostname && cat /etc/issue && uname -a
    echo "Kernel version:"
    uname -r
}

# Checking for exploitable configurations and misconfigurations
exploitable_configs_and_misconfigurations() {
    echo "[*] Checking for Exploitable Configurations and Misconfigurations..."
    dpkg -l | grep -iE 'apache|nginx|mysql|php'
    echo "Checking writable /etc/passwd and /etc/shadow..."
    [ -w /etc/passwd ] && echo "/etc/passwd is writable"
    [ -w /etc/shadow ] && echo "/etc/shadow is writable"
    echo "Checking for misconfigured services..."
    # Placeholder for specific service checks
    echo "Checking environment variables..."
    env | grep -iE 'path|mail|home'
    echo "Checking sudo permissions..."
    sudo -l
}

# Enumerate network interfaces, routes, and open ports
enumerate_network_info() {
    echo "[*] Enumerating Network Interfaces and Routes..."
    ip a
    route -n
    echo "[*] Enumerating Open Ports..."
    ss -tuln
}

# Check firewall rules and configurations
check_firewall_configs() {
    echo "[*] Checking Firewall Rules and Configurations..."
    if [ -f /etc/iptables/rules.v4 ]; then
        cat /etc/iptables/rules.v4
    else
        echo "No iptables configuration file found or access denied."
    fi
}

# Enumerate mounted and unmounted filesystems
enumerate_filesystems() {
    echo "[*] Enumerating Mounted Filesystems..."
    mount | grep "^/"
    echo "[*] Checking for Unmounted Drives..."
    lsblk
    echo "[*] Viewing all drives that will be mounted at boot-time..."
    cat /etc/fstab
}

# Check for writable directories
check_writable_directories() {
    echo "[*] Checking for Writable Directories..."
    find / -type d -writable 2>/dev/null
}

# Inspect environment variables and hidden files for sensitive info
inspect_env_and_hidden_files() {
    echo "[*] Inspecting Environment Variables for Sensitive Info..."
    env | grep -i password
    echo "[*] Searching for Exposed Confidential Information in Hidden Files..."
    find /home -type f -name ".*" -print 2>/dev/null
}

# Combining all checks
main() {
    echo "Enhanced checks for Linux Privilege Escalation"
    check_docker_group
    enumerate_cron_and_at_jobs
    identify_suid_binaries
    check_world_writable_files
    review_processes
    search_plaintext_passwords_and_sensitive_files
    network_system_info_and_kernel_version
    exploitable_configs_and_misconfigurations
    enumerate_network_info
    check_firewall_configs
    enumerate_filesystems
    check_writable_directories
    inspect_env_and_hidden_files
    echo "Enhanced Privilege Escalation and Enumeration Checks Completed."
}

# Execute main function
main
