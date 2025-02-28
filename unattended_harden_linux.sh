#!/bin/bash

# This version of the Linux hardening script has defaults in place and no user input.
# This allows headless execution for servers.
# This is intended to be run as root on first startup for a Vultr VPS.
# WARNING: Check logs before assuming that everything executed fine.
# Consider a trust review of third-party installed packages:
# - Fail2Ban
# - ClamAV / ClamAV-Daemon
# - AppArmor / AppArmor-Utils
# - AIDE

# Global variables
BACKUP_DIR="/root/security_backup_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="/var/log/unattended_hardening.log"
SCRIPT_NAME=$(basename "$0")

# Function for logging
log() {
    local message="$(date '+%Y-%m-%d %H:%M:%S'): $1"
    echo "$message" >> "$LOG_FILE"
}

# Function for error handling
handle_error() {
    log "Error: $1"
    exit 1
}

# Function to install packages
install_package() {
    log "Installing $1..."
    DEBIAN_FRONTEND=noninteractive apt-get install -y "$1" || handle_error "Failed to install $1"
}

# Function to backup files
backup_files() {
    mkdir -p "$BACKUP_DIR" || handle_error "Failed to create backup directory"
    
    local files_to_backup=(
        "/etc/default/grub"
        "/etc/ssh/sshd_config"
        "/etc/pam.d/common-password"
        "/etc/login.defs"
        "/etc/sysctl.conf"
    )
    
    for file in "${files_to_backup[@]}"; do
        if [ -f "$file" ]; then
            cp "$file" "$BACKUP_DIR/" || log "Warning: Failed to backup $file"
        else
            log "Warning: $file not found, skipping backup"
        fi
    done
    
    log "Backup created in $BACKUP_DIR"
}

# Function to check permissions
check_permissions() {
    if [ "$EUID" -ne 0 ]; then
        echo "This script must be run as root."
        exit 1
    fi
}

# Function to display help
display_help() {
    echo "Usage: # ./$SCRIPT_NAME"
    exit 0
}

# Function to check system requirements
check_requirements() {
    if ! command -v lsb_release &> /dev/null; then
        handle_error "lsb_release command not found. This script requires an Ubuntu-based system."
    fi

    local os_name=$(lsb_release -si)
    local os_version=$(lsb_release -sr)

    if [[ "$os_name" != "Ubuntu" && "$os_name" != "Debian" ]]; then
        handle_error "This script is designed for Ubuntu or Debian-based systems. Detected OS: $os_name"
    fi

    if [[ $(echo "$os_version < 18.04" | bc) -eq 1 ]]; then
        handle_error "This script requires Ubuntu 18.04 or later. Detected version: $os_version"
	elif [[ "$os_name" == "Debian" && $(echo "$os_version < 12.0" | bc) -eq 1 ]]; then
	handle_error "This script requires Debian 12.0 or later. Detected version: $os_version"
    fi

    log "System requirements check passed. OS: $os_name $os_version"
}

# Function to update system
update_system() {
    log "Updating System..."
    apt-get update -y || handle_error "System update failed"
    DEBIAN_FRONTEND=noninteractive apt-get upgrade -y || handle_error "System upgrade failed"
}

# Function to setup firewall
setup_firewall() {
    log "Installing and Configuring Firewall..."
    install_package "ufw"
    ufw default deny incoming || handle_error "Failed to set UFW default incoming policy"
    ufw default allow outgoing || handle_error "Failed to set UFW default outgoing policy"
    ufw limit ssh comment 'Allow SSH with rate limiting' || handle_error "Failed to configure SSH in UFW"
    ufw allow 80/tcp comment 'Allow HTTP' || handle_error "Failed to allow HTTP in UFW"
    ufw allow 443/tcp comment 'Allow HTTPS' || handle_error "Failed to allow HTTPS in UFW"
    
    log "Applying IPv6-specific firewall rules..."
    ufw allow in on lo || handle_error "Failed to allow loopback traffic"
    ufw allow out on lo || handle_error "Failed to allow loopback traffic"
    ufw deny in from ::/0 || handle_error "Failed to deny all incoming IPv6 traffic"
    ufw allow out to ::/0 || handle_error "Failed to allow all outgoing IPv6 traffic"
    log "IPv6 firewall rules applied"
    
    ufw logging on || handle_error "Failed to enable UFW logging"
    ufw --force enable || handle_error "Failed to enable UFW"
    log "Firewall configured and enabled"
}

# Function to setup Fail2Ban
setup_fail2ban() {
    log "Installing and Configuring Fail2Ban..."
    install_package "fail2ban"
    cp /etc/fail2ban/jail.conf /etc/fail2ban/jail.local || handle_error "Failed to create Fail2Ban local config"
    sed -i 's/bantime  = 10m/bantime  = 1h/' /etc/fail2ban/jail.local || handle_error "Failed to set Fail2Ban bantime"
    sed -i 's/maxretry = 5/maxretry = 3/' /etc/fail2ban/jail.local || handle_error "Failed to set Fail2Ban maxretry"
    systemctl enable fail2ban || handle_error "Failed to enable Fail2Ban service"
    systemctl start fail2ban || handle_error "Failed to start Fail2Ban service"
    log "Fail2Ban configured and started"
}

# Function to setup ClamAV
setup_clamav() {
    log "Installing and Updating ClamAV..."
    install_package "clamav"
    install_package "clamav-daemon"
    systemctl stop clamav-freshclam || log "Warning: Failed to stop clamav-freshclam"
    freshclam || log "Warning: ClamAV database update failed"
    systemctl start clamav-freshclam || handle_error "Failed to start clamav-freshclam"
    systemctl enable clamav-freshclam || handle_error "Failed to enable clamav-freshclam"
    log "ClamAV installed and updated"
}

# Function to disable root login
disable_root() {
    log "Checking for non-root users with sudo privileges..."
    
    # Get the list of users with sudo privileges
    sudo_users=$(getent group sudo | cut -d: -f4 | tr ',' '\n' | grep -v "^root$")
    
    # Check if there are any non-root users with sudo privileges
    if [ -z "$sudo_users" ]; then
        log "Warning: No non-root users with sudo privileges found. Skipping root login disable for safety."
        echo "Please create a non-root user with sudo privileges before disabling root login."
        return
    fi
    
    log "Non-root users with sudo privileges found. Proceeding to disable root login..."
    
    # Disable root login
    if passwd -l root; then
        log "Root login disabled successfully."
    else
        handle_error "Failed to lock root account"
    fi
    
    # Disable root SSH login as an additional precaution
    if grep -q "^PermitRootLogin" /etc/ssh/sshd_config; then
        sed -i 's/^PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || handle_error "Failed to disable root SSH login in sshd_config"
    else
        echo "PermitRootLogin no" | tee -a /etc/ssh/sshd_config > /dev/null || handle_error "Failed to add PermitRootLogin no to sshd_config"
    fi
    
    # Restart SSH service to apply changes
    systemctl restart sshd || handle_error "Failed to restart SSH service"
    
    log "Root login has been disabled and SSH root login has been explicitly prohibited."
}

# Function to remove unnecessary packages
remove_packages() {
    log "Removing unnecessary packages..."
    DEBIAN_FRONTEND=noninteractive apt-get remove --purge -y telnetd nis yp-tools rsh-client rsh-redone-client xinetd || log "Warning: Failed to remove some packages"
    apt-get autoremove -y || log "Warning: autoremove failed"
    log "Unnecessary packages removed"
}

# Function to setup audit
setup_audit() {
    log "Configuring audit rules..."
    install_package "auditd"
    
    local audit_rules=(
        "-w /etc/passwd -p wa -k identity"
        "-w /etc/group -p wa -k identity"
        "-w /etc/shadow -p wa -k identity"
        "-w /etc/sudoers -p wa -k sudoers"
        "-w /var/log/auth.log -p wa -k auth_log"
        "-w /sbin/insmod -p x -k modules"
        "-w /sbin/rmmod -p x -k modules"
        "-w /sbin/modprobe -p x -k modules"
        "-w /var/log/faillog -p wa -k logins"
        "-w /var/log/lastlog -p wa -k logins"
        "-w /var/run/utmp -p wa -k session"
        "-w /var/log/wtmp -p wa -k session"
        "-w /var/log/btmp -p wa -k session"
        "-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change"
        "-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change"
        "-a always,exit -F arch=b64 -S clock_settime -k time-change"
        "-a always,exit -F arch=b32 -S clock_settime -k time-change"
        "-w /etc/localtime -p wa -k time-change"
    )
    
    for rule in "${audit_rules[@]}"; do
        echo "$rule" | tee -a /etc/audit/rules.d/audit.rules > /dev/null || handle_error "Failed to add audit rule: $rule"
    done
    
    systemctl enable auditd || handle_error "Failed to enable auditd service"
    systemctl start auditd || handle_error "Failed to start auditd service"
    log "Audit rules configured and auditd started"
}

# Function to disable unused filesystems
disable_filesystems() {
    log "Disabling Unused Filesystems..."
    local filesystems=("cramfs" "freevxfs" "jffs2" "hfs" "hfsplus" "squashfs" "udf" "vfat")
    
    for fs in "${filesystems[@]}"; do
        echo "install $fs /bin/true" | tee -a /etc/modprobe.d/CIS.conf > /dev/null || handle_error "Failed to disable filesystem: $fs"
    done
    
    log "Unused filesystems disabled"
}

# Function to secure boot settings
secure_boot() {
    log "Securing Boot Settings..."
    
    # Secure GRUB configuration file
    if [ -f /boot/grub/grub.cfg ]; then
        chown root:root /boot/grub/grub.cfg || handle_error "Failed to change ownership of grub.cfg"
        chmod 600 /boot/grub/grub.cfg || handle_error "Failed to change permissions of grub.cfg"
        log "GRUB configuration file secured"
    else
        log "Warning: /boot/grub/grub.cfg not found. Skipping GRUB file permissions."
    fi
    
    # Modify kernel parameters
    if [ -f /etc/default/grub ]; then
        # Backup original file
        cp /etc/default/grub /etc/default/grub.bak || handle_error "Failed to backup grub file"
        
        # Add or modify kernel parameters
        local kernel_params="audit=1 net.ipv4.conf.all.rp_filter=1 net.ipv4.conf.all.accept_redirects=0 net.ipv4.conf.all.send_redirects=0"
        
        # Consider disabling SACK
        #log "TCP SACK will be disabled"
        #kernel_params+=" net.ipv4.tcp_sack=0"
        log "TCP SACK will remain enabled"
        
        sed -i "s/GRUB_CMDLINE_LINUX=\"\"/GRUB_CMDLINE_LINUX=\"$kernel_params\"/" /etc/default/grub || handle_error "Failed to modify kernel parameters"
        
        # Update GRUB
        if command -v update-grub &> /dev/null; then
            update-grub || handle_error "Failed to update GRUB"
        elif command -v grub2-mkconfig &> /dev/null; then
            grub2-mkconfig -o /boot/grub2/grub.cfg || handle_error "Failed to update GRUB"
        else
            log "Warning: Neither update-grub nor grub2-mkconfig found. Please update GRUB manually."
        fi
        
        log "Kernel parameters updated"
    else
        log "Warning: /etc/default/grub not found. Skipping kernel parameter modifications."
    fi
    
    log "Boot settings secured"
}

# Function to disable IPv6
disable_ipv6() {
    log "Disabling IPv6..."
    echo "net.ipv6.conf.all.disable_ipv6 = 1" | tee -a /etc/sysctl.conf || handle_error "Failed to disable IPv6 (all)"
    echo "net.ipv6.conf.default.disable_ipv6 = 1" | tee -a /etc/sysctl.conf || handle_error "Failed to disable IPv6 (default)"
    echo "net.ipv6.conf.lo.disable_ipv6 = 1" | tee -a /etc/sysctl.conf || handle_error "Failed to disable IPv6 (lo)"
    sysctl -p || handle_error "Failed to apply sysctl changes"
    log "IPv6 has been disabled"
}

# Function to setup AppArmor
setup_apparmor() {
    log "Setting up AppArmor..."
    
    if ! command -v apparmor_status &> /dev/null; then
        install_package "apparmor"
        install_package "apparmor-utils"
    else
        log "AppArmor is already installed. Skipping installation."
    fi

    systemctl enable apparmor || handle_error "Failed to enable AppArmor service"
    systemctl start apparmor || handle_error "Failed to start AppArmor service"
    aa-enforce /etc/apparmor.d/* || log "Warning: Failed to enforce some AppArmor profiles"

    log "AppArmor setup complete. All profiles are in enforce mode."
    log "Monitor /var/log/syslog and /var/log/auth.log for any AppArmor-related issues."
}

# Function to setup NTP
setup_ntp() {
    log "Setting up time synchronization..."
    
    # Check if systemd-timesyncd is available (modern Ubuntu systems)
    if systemctl list-unit-files | grep -q systemd-timesyncd.service; then
        log "Using systemd-timesyncd for time synchronization"
        systemctl enable systemd-timesyncd.service || handle_error "Failed to enable systemd-timesyncd service"
        systemctl start systemd-timesyncd.service || handle_error "Failed to start systemd-timesyncd service"
        log "systemd-timesyncd setup complete"
    else
        # Fall back to NTPsec if systemd-timesyncd is not available
        log "Using NTPsec for time synchronization"
        install_package "ntpsec"
        systemctl enable ntpsec || handle_error "Failed to enable NTP service"
        systemctl start ntpsec || handle_error "Failed to start NTP service"
        log "NTP setup complete"
    fi
}

# Function to setup AIDE
setup_aide() {
    log "Setting up AIDE..."
    install_package "aide"
    aideinit || handle_error "Failed to initialize AIDE database"
    mv /var/lib/aide/aide.db.new /var/lib/aide/aide.db || handle_error "Failed to move AIDE database"
    log "AIDE setup complete"
}

# Function to configure sysctl
configure_sysctl() {
    log "Configuring sysctl settings..."
    
    local sysctl_config=(
        "# IP Spoofing protection"
        "net.ipv4.conf.all.rp_filter = 1"
        "net.ipv4.conf.default.rp_filter = 1"
        ""
        "# Ignore ICMP broadcast requests"
        "net.ipv4.icmp_echo_ignore_broadcasts = 1"
        ""
        "# Disable source packet routing"
        "net.ipv4.conf.all.accept_source_route = 0"
        "net.ipv6.conf.all.accept_source_route = 0"
        ""
        "# Ignore send redirects"
        "net.ipv4.conf.all.send_redirects = 0"
        "net.ipv4.conf.default.send_redirects = 0"
        ""
        "# Block SYN attacks"
        "net.ipv4.tcp_syncookies = 1"
        "net.ipv4.tcp_max_syn_backlog = 2048"
        "net.ipv4.tcp_synack_retries = 2"
        "net.ipv4.tcp_syn_retries = 5"
        ""
        "# Log Martians"
        "net.ipv4.conf.all.log_martians = 1"
        "net.ipv4.icmp_ignore_bogus_error_responses = 1"
        ""
        "# Ignore ICMP redirects"
        "net.ipv4.conf.all.accept_redirects = 0"
        "net.ipv6.conf.all.accept_redirects = 0"
        ""
        "# Ignore Directed pings"
        "net.ipv4.icmp_echo_ignore_all = 1"
        ""
        "# Enable ASLR"
        "kernel.randomize_va_space = 2"
        ""
        "# Increase system file descriptor limit"
        "fs.file-max = 65535"
        ""
        "# Allow for more PIDs"
        "kernel.pid_max = 65536"
        ""
        "# Protect against kernel pointer leaks"
        "kernel.kptr_restrict = 1"
        ""
        "# Restrict dmesg access"
        "kernel.dmesg_restrict = 1"
        ""
        "# Restrict kernel profiling"
        "kernel.perf_event_paranoid = 2"
    )
    
    printf "%s\n" "${sysctl_config[@]}" | tee -a /etc/sysctl.conf || handle_error "Failed to update sysctl.conf"
    sysctl -p || handle_error "Failed to apply sysctl changes"
    log "sysctl settings configured"
}

# Function for additional security measures
additional_security() {
    log "Applying additional security measures..."
    
    # Disable core dumps
    echo "* hard core 0" | tee -a /etc/security/limits.conf || handle_error "Failed to disable core dumps"
    
    # Set proper permissions on sensitive files
    chmod 600 /etc/shadow || handle_error "Failed to set permissions on /etc/shadow"
    chmod 600 /etc/gshadow || handle_error "Failed to set permissions on /etc/gshadow"
    
    # Enable process accounting
    install_package "acct"
    /usr/sbin/accton on || handle_error "Failed to enable process accounting"
    
    # Restrict SSH
    sed -i 's/^#PermitRootLogin.*/PermitRootLogin no/' /etc/ssh/sshd_config || handle_error "Failed to disable root login via SSH"
    sed -i 's/^#PasswordAuthentication.*/PasswordAuthentication no/' /etc/ssh/sshd_config || handle_error "Failed to disable password authentication for SSH"
    sed -i 's/^#Protocol.*/Protocol 2/' /etc/ssh/sshd_config || handle_error "Failed to set SSH protocol version"
    systemctl restart sshd || handle_error "Failed to restart SSH service"
    
    # Configure strong password policy
    sed -i 's/PASS_MAX_DAYS\t99999/PASS_MAX_DAYS\t90/' /etc/login.defs || handle_error "Failed to set password max days"
    sed -i 's/PASS_MIN_DAYS\t0/PASS_MIN_DAYS\t7/' /etc/login.defs || handle_error "Failed to set password min days"
    sed -i 's/password.*pam_unix.so.*/password    [success=1 default=ignore]    pam_unix.so obscure sha512 minlen=14 remember=5/' /etc/pam.d/common-password || handle_error "Failed to configure password policy"
    
    log "Additional security measures applied"
}

# Function to setup automatic updates
setup_automatic_updates() {
    log "Setting up automatic security updates..."
    install_package "unattended-upgrades"
    dpkg-reconfigure -plow unattended-upgrades || handle_error "Failed to configure unattended-upgrades"
    log "Automatic security updates configured"
}

# Main function
main() {
    # Parse command line arguments
    while [[ $# -gt 0 ]]; do
        case $1 in
            *)
                echo "Unknown option: $1"
                display_help
                ;;
        esac
    done

    check_permissions
    check_requirements
    backup_files

    update_system
    setup_firewall
    setup_fail2ban
    setup_clamav
    disable_root
    remove_packages
    setup_audit
    disable_filesystems
    secure_boot
    #disable_ipv6
    setup_apparmor
    setup_ntp
    setup_aide
    configure_sysctl
    additional_security
    setup_automatic_updates
    
    log "Enhanced Security Configuration executed! Script by captainzero93"

    log "Restarting system..."
    reboot
}

# Run the main function
main "$@"

