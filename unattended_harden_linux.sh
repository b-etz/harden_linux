#!/bin/bash

# This version of the Linux hardening script has defaults in place and no user input.
# This allows headless execution for servers.
# This is intended to be run as root on first startup for a Vultr/Crunchbits VPS.
# WARNING: Check logs before assuming that everything executed fine.
# Consider a trust review of third-party installed packages:
# - Fail2Ban

# Global variables
BACKUP_DIR="/root/security_backup_$(date +%Y%m%d_%H%M%S)"
LOG_FILE="/var/log/unattended_hardening.log"
SCRIPT_NAME=$(basename "$0")
SOURCE_DIR=$(dirname "$BASH_SOURCE")

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
        "/etc/pam.d/common-password"
        "/etc/login.defs"
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
    ufw default deny outgoing || handle_error "Failed to set UFW default outgoing policy"
    ufw limit ssh comment 'Allow SSH with rate limiting' || handle_error "Failed to configure SSH in UFW"
    # ufw allow 80/tcp comment 'Allow HTTP services' || handle_error "Failed to allow HTTP server in UFW"
    # ufw allow 443/tcp comment 'Allow HTTPS services' || handle_error "Failed to allow HTTPS server in UFW"
    # ufw allow 53/udp comment 'Allow DNS services' || handle_error "Failed to allow DNS server in UFW"
    ufw allow out 53/udp comment 'Allow DNS queries' || handle_error "Failed to allow DNS queries in UFW"
    ufw allow out 80 comment 'Allow HTTP queries' || handle_error "Failed to allow HTTP queries in UFW"
    ufw allow out 123/udp comment 'Allow NTP sync' || handle_error "Failed to allow outgoing NTP in UFW"
    ufw allow out 443 comment 'Allow HTTPS queries' || handle_error "Failed to allow HTTPS queries in UFW"
    ufw allow out 853 comment 'Allow DoT queries' || handle_error "Failed to allow DNS-over-TLS queries in UFW"
    ufw allow in on lo || handle_error "Failed to allow loopback traffic"
    ufw allow out on lo || handle_error "Failed to allow loopback traffic"

    install_package "rsyslog"
    ufw logging on || handle_error "Failed to enable UFW logging"
    ufw --force enable || handle_error "Failed to enable UFW"
    log "Firewall configured and enabled"
}

# Function to setup Fail2Ban
setup_fail2ban() {
    log "Installing and Configuring Fail2Ban..."
    install_package "fail2ban"
    cp $SOURCE_DIR/inc/jail.local /etc/fail2ban || handle_error "Failed to create Fail2Ban local config"
    cp $SOURCE_DIR/inc/ufw-aggressive.conf /etc/fail2ban/filter.d || handle_error "Failed to create Fail2Ban ufw filter"
    systemctl enable fail2ban || handle_error "Failed to enable Fail2Ban service"
    systemctl start fail2ban || handle_error "Failed to start Fail2Ban service"
    log "Fail2Ban configured and started"
}

# Function to disable root login
disable_root() {
    log "Checking for non-root users with sudo privileges..."
    sudo_users=$(getent group sudo | cut -d: -f4 | tr ',' '\n' | grep -v "^root$")
    if [ -z "$sudo_users" ]; then
        log "Warning: No non-root users with sudo privileges found. Skipping root login disable for safety."
        echo "Please create a non-root user with sudo privileges before disabling root login."
        return
    fi

    log "Non-root users with sudo privileges found. Proceeding to disable root login..."
    passwd -l root || handle_error "Failed to lock root account"

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
    cp -f $SOURCE_DIR/inc/audit.rules /etc/audit/rules.d/audit.rules || handle_error "Failed to copy custom audit rule deck"
    systemctl enable auditd || handle_error "Failed to enable auditd service"
    systemctl start auditd || handle_error "Failed to start auditd service"
    log "Audit rules configured and auditd started"
}

# Function to disable unused filesystems
disable_filesystems() {
    log "Disabling Unused Filesystems..."
    cp $SOURCE_DIR/inc/fs-disable.conf /etc/modprobe.d || handle_error "Failed to create filesystem module blacklist"
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

# Function to configure sysctl
configure_sysctl() {
    log "Configuring sysctl settings..."
    cp $SOURCE_DIR/inc/local.conf /etc/sysctl.d || handle_error "Failed to create sysctl.d conf"
    if [ -f /etc/default/ufw ]; then
        sed -i 's/^IPT_SYSCTL=.*/#IPT_SYSCTL=/' /etc/default/ufw || handle_error "Failed to disable UFW sysctl override"
    fi
    sysctl -p /etc/sysctl.d/local.conf || handle_error "Failed to apply sysctl changes"
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

    # Restrict SSH and enable verbose logging
    cp -f $SOURCE_DIR/inc/10-hardened-ssh.conf /etc/ssh/sshd_config.d/10-hardened-ssh.conf || handle_error "Failed to copy sshd config file"
    systemctl restart sshd || handle_error "Failed to restart SSH service"

    log "Additional security measures applied"
}

# Function to setup automatic updates
setup_automatic_updates() {
    log "Setting up automatic security updates..."
    install_package "unattended-upgrades"
    echo unattended-upgrades unattended-upgrades/enable_auto_updates boolean true | debconf-set-selections
    dpkg-reconfigure -f noninteractive unattended-upgrades || handle_error "Failed to configure unattended-upgrades"
    log "Automatic security updates configured"
}

# Main function
main() {
    backup_files
    update_system

    setup_firewall
    setup_fail2ban
    disable_root
    remove_packages
    setup_audit
    disable_filesystems
    secure_boot
    disable_ipv6
    setup_ntp
    configure_sysctl
    additional_security
    setup_automatic_updates

    log "Enhanced Security Configuration executed! Script by captainzero93"
    log "Restarting system..."
    reboot
}

# Run the main function
main "$@"
