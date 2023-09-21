#!/bin/bash
###############################################################
#####################FUNCTIONS#################################
###############################################################
function set_mount_fs() { 
	file=/etc/modprobe.d/$1.conf
	if [ ! -e $file ]; then
		echo "#CIS config" > $file
	fi
	if ! grep "$1" $file; then
		sed -i "$ a install $1 /bin/true" $file
		rmmod $1
	fi
		
}

function option_partition(){
	if sed -n '/\/$1/p' /etc/fstab | grep 'nodev' && sed -n '/\/$1/p' /etc/fstab | grep 'noexec' && sed -n '/\/$1/p' /etc/fstab | grep 'nosuid'; then
		sed -i '/\/$1/s/defaults/defaults,nodev,noexec,nosuid/g' /etc/fstab
	fi
}

function set_directive(){
	if [ -e $3 ]; then
		if ! grep "^$1" $3; then
			sed -i "$ a $1=$2" $3
		else 
			sed -i "/^$1/ c $1=$2" $3
		fi
	fi
}

function inetd_disabled(){
	if [ -e /etc/inetd.conf ]; then
		sed -i "/^$1/d" /etc/inetd.conf	
	fi
}

function add_parameter(){
	if [ -e $3 ]; then
		if ! grep "^$1" $3; then
			sed -i "$ a $1$2" $3
 		else 
 			sed -i "/^$1/ c $1$2" $3
 		fi
	fi
}

function rm_file(){
	check=$(find / -name "$1" -type f 2>/dev/null)
	if [ -n "$check" ];then
		for file in $check; do
			rm -rf "$file"
		done
	fi
}
###############################################################

#=================================== 1 Initial Setup ================================

#1.1 Filesystem configuration#
#1.1.1 Disable unused filesystems
#1.1.1.1 Ensure mounting of freevxfs filesystems is disabled (Scored) 
#1.1.1.2 Ensure mounting of jffs2 filesystems is disabled (Scored) 
#1.1.1.3 Ensure mounting of hfs filesystems is disabled (Scored) 
#1.1.1.4 Ensure mounting of hfsplus filesystems is disabled (Scored)
#1.1.1.5 Ensure mounting of udf filesystems is disabled (Scored)
#1.1.23 Disable USB Storage (Scored)
fs_mount=("cramfs" "freevxfs" "jffs2" "hfs" "hfsplus" "squashfs" "udf" "fstab" "usb-storage")
for val in ${fs_mount[@]};
do
	set_mount_fs $val
done
#1.1.2 Ensure /tmp is configured
if [ ! -e /etc/systemd/system/tmp.mount ]; then
	cp /usr/share/systemd/tmp.mount /etc/systemd/system
fi
systemctl enable tmp.mount

#1.1.3 Ensure nodev option set on /tmp partition (Scored)
#1.1.4 Ensure nodev option set on /tmp partition (Scored)
#1.1.5 Ensure nodev option set on /tmp partition (Scored)
#1.1.8 Ensure nodev option set on /var/tmp partition (Scored)
#1.1.9 Ensure nodev option set on /var/tmp partition (Scored)
#1.1.10 Ensure nodev option set on /var/tmp partition (Scored)
#1.1.15 Ensure nodev option set on /dev/shm partition (Scored)
#1.1.16 Ensure nodev option set on /dev/shm partition (Scored)
#1.1.17 Ensure nodev option set on /shm/dev partition (Scored)
partition=("tmp" "var/tmp" "dev/shm")
for val in ${partition[@]};
do
	option_partition $val
done
#1.1.14 Ensure nodev option set on /home partition (Scored)
if sed -n '/\/$1/p' /etc/fstab | grep 'nodev' ; then sed -i '/\/$1/s/defaults/defualts,nodev,noexec,nosuid/g' /etc/fstab;fi
#1.1.21 Ensure sticky bit is set on all world-writable directories (Scored)
if df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' -xdev -type d \(-perm -0002 -a ! -perm -1000 \) 2>/dev/null; then
	df --local -P | awk '{if (NR!=1) print $6}' | xargs -I '{}' -xdev -type d \(-perm -0002 -a ! -perm -1000 \) 2>/dev/null | xargs -I '{}' chmod a+t '{}'
fi
#1.1.22 Disable Automouting (Scored)
systemctl disable autofs
#1.2 Configure Software Updates#
#1.2.1 Ensure package manager repositories are configured (Not Scored)
#1.2.2 Ensure GPG keys are configured (Not Scored)
#1.3 Filesystem Integrity checking#
#1.3.1 Ensure AIDE is installed
apt-get -y install aide aide-common
aideinit
#1.3.2 Ensure filesystem intergrity is regularly checked (Scored)
sed -i "$ a 0 5 * * * /usr/sbin/aide --check" >> /etc/crontab
#1.4 Secure boot settings#
#1.4.1 Ensure permissions on bootloader config are configured (Scored)
chown root:root /boot/grub/grub.cfg
chmod og-rwx /boot/grub/grub.cfg
#1.4.2 Ensure bootloader password is set (Scored)
echo "########Create bootloader password########"

if ! grep -o "password" /etc/grub.d/00_header;then
	echo "[Enter username:]"
	read username
	echo "[Enter password 2 times (Enter the 1st time, then enter again the 2nd time)]"
	encryptpass=$(grub-mkpasswd-pbkdf2 | grep -oP "(?<=PBKDF2 hash of your password is ).*")
	echo "cat <<EOF
	set superusers=\"$username\"
	password_pbkdf2 $username $encryptpass
	EOF" >> /etc/grub.d/00_header 
	update-grub
fi
#1.4.3 Ensure authentication required for single user mode (Scored)
if grep ^root:[*\!]: /etc/shadow; then
	echo "[Enter password for root]"
	passwd root
fi
#1.5 Additional Process Harderning#
#1.5.1 Ensure core dumps are restricted (Scored)
if ! grep "hard core" /etc/security/limits.conf; then sed -i "$ a hard core 0" /etc/security/limits.conf; fi
set_directive "fs.suid_dumpable" 0 "/etc/sysctl.conf"
sysctl -w fs.suid_dumpable=0
#1.5.2 Ensure XD/NX support is enabled (Scored)
#1.5.3 Ensure address space layout randomization
set_directive "kernel.randomize_va_space" 2 "/etc/sysctl.conf"
sysctl -w kernel.randomize_va_space=2
#1.5.4 Ensure prelink is disabled 
prelink -ua
apt-get remove prelink
#1.6 Madatory Access Control
#1.6.1 Ensure Madatory Access control software is installed
apt-get install libselinux1
apt-get install apparmor
#1.6.2 Configure SELinux
#1.6.2.1 Ensure SELInux is disabled in booloader configuration
sed -i '/^GRUB_CMDLINE_LINUX_DEFAULT=/ c GRUB_CMDLINE_LINUX_DEFAULT=\"quiet\"' /etc/default/grub
sed -i '/^GRUB_CMDLINE_LINUX=/ c GRUB_CMDLINE_LINUX=\"\"' /etc/default/grub
update-grub
#1.6.2.2 Ensure the SELinux state is enforcing (Scored)
if [ ! -e /etc/selinux/config ]; then
	echo "SELINUX=enforcing" >> /etc/selinux/config
else 
	if ! grep "^SELINUX=" /etc/selinux/config; then
		sed -i '$ a SELINUX=enforcing' /etc/selinux/config
	else 
		sed -i '/^SELINUX=/ c SELINUX=enforcing' /etc/selinux/config
	fi
fi
#1.6.2.3 Ensure SELinux policy is configured (Scored)
if [ ! -e /etc/selinux/config ]; then
	echo "SELINUXTYPE=targeted" >> /etc/selinux/config
else 
	if ! grep "^SELINUXTYPE=" /etc/selinux/config; then
		sed -i '$ a SELINUXTYPE=targeted' /etc/selinux/config
	else 
		sed -i '/^SELINUXTYPE=/ c SELINUXTYPE=targeted' /etc/selinux/config
	fi
fi
#1.6.2.4 Ensure SETroubleshoot is not installed (Scored)
apt-get remove setroubleshoot
#1.6.2.5 Ensure the MCS Translation Service is not installed (Scored)
apt-get remove msctrans
#1.6.2.6 Ensure no unconfined daemons exist (Scored)
#1.6.3 Configure AppArmor
#1.6.3.1 Ensure SELInux is disabled in booloader configuration (Scored)
#1.6.3.2 Ensure all AppArmor Profiles are enforcing (Scored)
enforce /etc/apparmor.d/*
#1.7 Warning Banners
#1.7.1 Command line warning banners
#1.7.1.1 Ensure message of the day is configured properly (Scored)
read -s -p "Enter message of the day for configure:" message
echo "$message" > /etc/motd
#1.7.1.2 Ensure local login warning banner is configured properly (Scored)
echo "Authorized uses only. All activity may be monitored and reported." >> /etc/issue
#1.7.1.3 Ensure remote login warning banner is configured properly (Scored)
echo "Authorized uses only. All activity may be monitored and reported." >> /etc/issue.net
#1.7.1.4 Ensure permissions on /etc/motd are configured (Scored)
chown root:root /etc/motd
chmod 644 /etc/motd
#1.7.1.5 Ensure permissions on /etc/issue are configured (Scored)
chown root:root /etc/issue
chmod 644 /etc/issue
#1.7.1.6 Ensure permissions on /etc/issue.net are configured (Scored)
chown root:root /etc/issue.net
chmod 644 /etc/issue.net
#1.7.2 Ensure GDM login banner is configured (Scored)
echo "
[org/gnome/login-screen]
banner-message-enable=true
banner-message-text='Authorized uses only. All activity may be moniored and reported.'
" >> /etc/gdm3/greeter.dconf-defaults
#1.8 Ensure updates, pathches, and additional security software are installed (Not Scored)
apt-get -y update


#============================== 2 Services =====================================
#2.1 inetd Services#
#2.1.1 Ensure chargen services are not enabled (Scored)
#2.1.2 Ensure daytime services are not enabled (Scored)
#2.1.3 Ensure discard services are not enabled (Scored)
#2.1.4 Ensure echo services are not enabled (Scored)
#2.1.5 Ensure time services are not enabled (Scored)
#2.1.6 Ensure rsh server is not enabled (Scored)
#2.1.7 Ensure talk server is not enabled (Scored)
#2.1.8 Ensure telnet server is not enabled (Scored)
#2.1.9 Ensure xinetd is not enabled (Scored)
inetd_services=("chargen" "daytime" "discard" "echo" "time" "shell" "login" "exec" "talk" "ntalk" "telnet" "tftp")
for val in "${inetd_services[@]}"
do
	inetd_disabled $val
done
apt-get -y remove xinetd
apt-get -y purge xinetd
#2.2 Special Purpose Services
#2.2.1 Time Synchronization
#2.2.1.1 Ensure time synchronization is in use (Not Scored)
apt-get -y install ntp
apt-get -y install chrony
#2.2.1.2 Ensure ntp is configured (Scored)
echo "
restrict -4 default kod nomodify notrap nopeer noquery
restrict -6 default kod nomodify notrap nopeer noquery
" > /etc/ntp.conf
read -s -p "Do you want to add remote-server for ntp? [y-yes/n-no]" ques1
if [ "$ques1" == "y" ]; then
	read -s -p "Enter remote-server: " remoteServer1
	echo "server $remoteServer1" >> /etc/ntp.conf
else
	echo "server pool.ntp,org" >> /etc/ntp.conf
fi
set_directive "RUNASUSER" "ntp" "/etc/init.d/ntp";
#2.2.1.3 Ensure chrony is configured (Scored)
read -s -p "Do you want to add remote-server for chronyd? [y-yes/n-no]" ques2
if [ "$ques2" == "y" ]; then
	read -s -p "Enter remote-server: " remoteServer2
	echo "server $remoteServer2" >> /etc/chrony.conf
else
	echo "server pool.ntp,org" >> /etc/chrony.conf
fi
#2.2.1.4 Ensure systemd-timesyncd is configured (Scored)
systemctl enable systemd-timesyncd.service
echo "
NTP=0.debian.pool.ntp.org 1.debian.pool.ntp.org
FallbackNTP=2.debian.pool.ntp.org 3.debian.pool.ntp.org
RootDistanceMax=1
" >> /etc/systemd/timesyncd.conf
systemctl start systemd-timesyncd.service
timedatectl set-ntp true
#2.2.2 Ensure X Window System is not installed (Scored)
apt-get -y remove xserver-xorg*
#2.2.3 Ensure Avahi Server is not enabled (Scored)
#2.2.4 Ensure CUPS is not enabled (Scored)
#2.2.5 Ensure DHCP Server is not enabled (Scored)
#2.2.6 Ensure LDAP server is not enabled (Scored)
#2.2.7 Ensure NFS and RPC are not enabled (Scored)
#2.2.8 Ensure DNS Server is not enabled (Scored)
#2.2.9 Ensure FTP Server is not enabled (Scored)
#2.2.10 Ensure HTTP server is not enabled (Scored)
#2.2.11 Ensure IMAP and POP3 server is not enabled (Scored)
#2.2.12 Ensure Samba is not enabled (Scored)
#2.2.13 Ensure HTTP Proxy Server is not enabled (Scored)
#2.2.14 Ensure SNMP server is not enabled (Scored)
#2.2.16 Ensure rsync service is not enabled (Scored)
#2.2.17 Ensure NIS Server is not enabled (Scored)
disServer=("avahi-daemon" "cups" "dhcpd" "nfs" "slapd" "rpcbind" "named" "vsftpd" "httpd" "dovecot" "smb" "squid" "snmpd" "rsyncd" "ypserv")
for val in "${disServer[@]}"
do
	systemctl disable $val
done
#2.2.15 Ensure mail transfer agent is configured for local-only mode (Scored)
if [ -e /etc/postfix/main.cf ]; then
	sed -i '/^inet_interfaces/ c inet_interfaces=loopback-only' /etc/postfix/main.cf
fi
systemctl restart postfix
service postfix restart
#2.3 Service Clients
#2.3.1 Ensure NIS client is not installed (Scored)
apt-get -y remove ypbind
#2.3.2 Ensure rsh client is not installed (Scored)
apt-get -y remove rsh
#2.3.3 Ensure talk client is not installed (Scored)
apt-get -y remove talk
#2.3.4 Ensure telnet client is not installed (Scored)
apt-get -y remove telnet
#2.3.5 Ensure LDAP client is not installed (Scored)
apt-get -y remove openldap-clients
#============================ 4 Logging and Auditing ==============================
#4.1 Configure System Accounting (auditd)
#4.1.1 Configure Data Retention
#4.1.2 Ensure auditd is installed (Scored)
apt-get -y install auditd audispd-plugins
#4.1.3 Ensure auditd service is enabled (Scored)
systemctl enable auditd
#4.1.1.1 Ensure audit log storage size is configured (Scored)
read -s -p "Enter audit log strorage size [MB]: " size
set_directive "max_log_file" $size "/etc/audit/auditd.conf"
#4.1.1.2 Ensure system is disabled when audit logs are full (Scored)
set_directive "space_left_action" "email" "/etc/audit/auditd.conf"
set_directive "action_mail_acct" "root" "/etc/audit/auditd.conf"
set_directive "admin_space_left_action" "halt" "/etc/audit/auditd.conf"
#4.1.1.3 Ensure audit logs are not automatically deleted (Scored)
set_directive "max_log_file_action" "keep_logs" "/etc/audit/auditd.conf"
#4.1.4 Ensure auditing for processes that start prior to auditd is enabled (Scored)
add_parameter "GRUB_CMDLINE_LINUX=" "\"audit=1\"" "/etc/default/grub"
update-grub
#4.1.5 Ensure events that modify date and time information are collected (Scored)
#4.1.6 Ensure events that modify user/group information are collected (Scored)
#4.1.7 Ensure events that modify the system's network environment are collected (Scored)
#4.1.8 Ensure events that modify the system's Mandatory Access Controls are collected (Scored)
#4.1.9 Ensure login and logout events are collected (Scored)
#4.1.10 Ensure session initiation information is collected (Scored)
#4.1.11 Ensure discretionary access control permission modification events are collected (Scored)
#4.1.12 Ensure unsuccessful unauthorized file access attempts are collected (Scored)
#4.1.14 Ensure successful file system mounts are collected (Scored)
#4.1.15 Ensure file deletion events by users are collected (Scored)
#4.1.16 Ensure changes to system administration scope (sudoers) is collected (Scored)
#4.1.17 Ensure system administrator actions (sudolog) are collected (Scored)
#4.1.18 Ensure kernel module loading and unloading is collected (Scored)
echo "
-a always,exit -F arch=b64 -S adjtimex -S settimeofday -k time-change
-a always,exit -F arch=b32 -S adjtimex -S settimeofday -S stime -k time-change
-a always,exit -F arch=b64 -S clock_settime -k time-change
-a always,exit -F arch=b32 -S clock_settime -k time-change
-a always,exit -F arch=b64 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b32 -S sethostname -S setdomainname -k system-locale
-a always,exit -F arch=b64 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chmod -S fchmod -S fchmodat -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S chown -S fchown -S fchownat -S lchown -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b32 -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=500 -F auid!=4294967295 -k perm_mod
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EACCES -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b32 -S creat -S open -S openat -S truncate -S ftruncate -F exit=-EPERM -F auid>=500 -F auid!=4294967295 -k access
-a always,exit -F arch=b64 -S mount -F auid>=500 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b32 -S mount -F auid>=500 -F auid!=4294967295 -k mounts
-a always,exit -F arch=b64 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b32 -S unlink -S unlinkat -S rename -S renameat -F auid>=500 -F auid!=4294967295 -k delete
-a always,exit -F arch=b64 -S init_module -S delete_module -k modules
-w /etc/localtime -p wa -k time-change
-w /etc/group -p wa -k identity
-w /etc/passwd -p wa -k identity
-w /etc/gshadow -p wa -k identity
-w /etc/shadow -p wa -k identity
-w /etc/security/opasswd -p wa -k identity
-w /etc/issue -p wa -k system-locale
-w /etc/issue.net -p wa -k system-locale
-w /etc/hosts -p wa -k system-locale
-w /etc/sysconfig/network -p wa -k system-locale
-w /etc/selinux/ -p wa -k MAC-policy
-w /usr/share/selinux/ -p wa -k MAC-policy
-w /etc/apparmor/ -p wa -k MAC-policy
-w /etc/apparmor.d/ -p wa -k MAC-policy
-w /var/log/faillog -p wa -k logins
-w /var/log/lastlog -p wa -k logins
-w /var/log/tallylog -p wa -k logins
-w /var/run/utmp -p wa -k session
-w /var/log/wtmp -p wa -k logins
-w /var/log/btmp -p wa -k logins
-w /etc/sudoers -p wa -k scope
-w /etc/sudoers.d/ -p wa -k scope
-w /var/log/sudo.log -p wa -k actions
-w /sbin/insmod -p x -k modules
-w /sbin/rmmod -p x -k modules
-w /sbin/modprobe -p x -k modules
" >> /etc/audit/rules.d/audit.rules

#4.1.13 Ensure use of privileged commands is collected (Scored)
find <partition> -xdev \( -perm -4000 -o -perm -2000 \) -type f | awk '{print "-a always,exit -F path=" $1 " -F perm=x -F auid>=500 -F auid!=4294967295 -k privileged" }'
#4.1.19 Ensure the audit configuration is immutable (Scored)
echo "-e 2" >> /etc/audit/rules.d/99-finalize.rules
#4.2 Configure Logging
#4.2.1 Configure rsyslog
#4.2.1.1 Ensure rsyslog is installed (Scored)
apt-get -y install rsyslog
#4.2.1.2 Ensure rsyslog Service is enabled (Scored)
systemctl enable rsyslog
#4.2.1.3 Ensure logging is configured (Not Scored)
#4.2.1.4 Ensure rsyslog default file permissions configured (Scored)
add_parameter "\$FileCreateMode " "0604" "/etc/rsyslog.conf"
#4.2.1.5 Ensure rsyslog is configured to send logs to a remote log host(Scored)
read -s -p "Enter your log host: " loghost
add_parameter "*.*" "$loghost" "/etc/rsyslog.conf"
pkill -HUP rsyslogd
#4.2.1.6 Ensure remote rsyslog messages are only accepted ondesignated log hosts. (Not Scored)
#4.2.2 Configure journald
#4.2.2.1 Ensure journald is configured to send logs to rsyslog (Scored)
set_directive "ForwardToSyslog" "yes" "/etc/systemd/journald.conf"
#4.2.2.2 Ensure journald is configured to compress large log files (Scored)
set_directive "Compress" "yes" "/etc/systemd/journald.conf"
#4.2.2.3 Ensure journald is configured to write logfiles to persistent disk (Scored)
set_directive "Storage" "persistent" "/etc/systemd/journald.conf"
#4.2.3 Ensure permissions on all logfiles are configured (Scored)
find /var/log -type f -exec chmod g-wx,o-rwx "{}" + -o -type d -exec chmod g-w,o-rwx "{}" +
#4.3 Ensure logrotate is configured (Not Scored)

#======================== 5 Access, Authentication and Authorization ==============
#5.1 Configure cron
#5.1.1 Ensure cron daemon is enabled (Scored)
systemctl enable crond
#5.1.2 Ensure permissions on /etc/crontab are configured (Scored)
#5.1.3 Ensure permissions on /etc/cron.hourly are configured (Scored)
#5.1.4 Ensure permissions on /etc/cron.daily are configured (Scored)
#5.1.5 Ensure permissions on /etc/cron.weekly are configured (Scored)
#5.1.6 Ensure permissions on /etc/cron.monthly are configured (Scored)
#5.1.7 Ensure permissions on /etc/cron.d are configured (Scored)
crontabList=("crontab" "cron.hourly" "cron.daily" "cron.weekly" "cron.monthly" "cron.d")
for val in "${crontabList[@]}"
do
	chown root:root /etc/$val
	chmod og-rwx /etc/$val
done
#5.1.8 Ensure at/cron is restricted to authorized users (Scored)
rm /etc/cron.deny
rm /etc/at.deny
touch /etc/cron.allow
touch /etc/at.allow
chmod og-rwx /etc/cron.allow
chmod og-rwx /etc/at.allow
chown root:root /etc/cron.allow
chown root:root /etc/at.allow
#5.2 SSH Server Configuration
#5.2.1 Ensure permissions on /etc/ssh/sshd_config are configured (Scored)
chown root:root /etc/ssh/ssh_config
chmod og-rwx /etc/ssh/ssh_config
#5.2.2 Ensure permissions on SSH private host key files are configured (Scored)
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chown root:root {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key' -exec chmod 0600 {} \;
#5.2.3 Ensure permissions on SSH public host key files are configured (Scored)
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chmod 0644 {} \;
find /etc/ssh -xdev -type f -name 'ssh_host_*_key.pub' -exec chown root:root {} \;
#5.2.4 Ensure SSH Protocol is set to 2 (Scored)
add_parameter "Protocol " 2 "/etc/ssh/sshd_config"
#5.2.5 Ensure SSH LogLevel is appropriate (Scored)
add_parameter "LogLevel " "INFO" "/etc/ssh/sshd_config"
#5.2.6 Ensure SSH X11 forwarding is disabled (Scored)
add_parameter "X11Forwarding " "no" "/etc/ssh/sshd_config"
#5.2.7 Ensure SSH MaxAuthTries is set to 4 or less (Scored)
add_parameter "MaxAuthTries " 4 "/etc/ssh/sshd_config"
#5.2.8 Ensure SSH IgnoreRhosts is enabled (Scored)
add_parameter "IgnoreRhosts " "yes" "/etc/ssh/sshd_config"
#5.2.9 Ensure SSH HostbasedAuthentication is disabled (Scored)
add_parameter "HostbasedAuthentication " "no" "/etc/ssh/sshd_config"
#5.2.10 Ensure SSH root login is disabled (Scored)
add_parameter "PermitRootLogin " "no" "/etc/ssh/sshd_config"
#5.2.11 Ensure SSH PermitEmptyPasswords is disabled (Scored)
add_parameter "PermitEmptyPasswords " "no" "/etc/ssh/sshd_config"
#5.2.12 Ensure SSH PermitUserEnvironment is disabled (Scored)
add_parameter "PermitUserEnvironment " "no" "/etc/ssh/sshd_config"
#5.2.13 Ensure only strong Ciphers are used (Scored)
add_parameter "Ciphers " "chacha20-poly1305@openssh.com,aes256-gcm@openssh.com,aes128-gcm@openssh.com,aes256-ctr,aes192-ctr,aes128-ctr" "/etc/ssh/sshd_config"
#5.2.14 Ensure only strong MAC algorithms are used (Scored)
add_parameter "MACs " "hmac-sha2-512-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512,hmac-sha2-256" "/etc/ssh/sshd_config"
#5.2.15 Ensure only strong Key Exchange algorithms are used (Scored)
add_parameter "KexAlgorithms " "curve25519-sha256,curve25519-sha256@libssh.org,diffie-hellman-group14-sha256,diffie-hellman-group16-sha512,diffie-hellman-group18-sha512,ecdh-sha2-nistp521,ecdh-sha2-nistp384,ecdh-sha2-nistp256,diffie-hellman-group-exchange-sha256" "/etc/ssh/sshd_config"
#5.2.16 Ensure SSH Idle Timeout Interval is configured (Scored)
add_parameter "ClientAliveInterval " 300 "/etc/ssh/sshd_config"
add_parameter "ClientAliveCountMax " 0 "/etc/ssh/sshd_config"
#5.2.17 Ensure SSH LoginGraceTime is set to one minute or less (Scored)
add_parameter "LoginGraceTime " 60 "/etc/ssh/sshd_config"
#5.2.18 Ensure SSH access is limited (Scored)
read -s -p "Enter user allow ssh access: " userl
read -s -p "\nEnter group allow ssh access: " groupl
add_parameter "AllowUsers " "$userl" "/etc/ssh/sshd_config"
add_parameter "AllowGroups " "$groupl" "/etc/ssh/sshd_config"
#5.2.19 Ensure SSH warning banner is configured (Scored)
add_parameter "Banner " "/etc/issue.net" "/etc/ssh/sshd_config"
#5.2.20 Ensure SSH PAM is enabled (Scored)
add_parameter "UsePAM " "yes" "/etc/ssh/sshd_config"
#5.2.21 Ensure SSH AllowTcpForwarding is disabled (Scored)
add_parameter "AllowTcpForwarding " "no" "/etc/ssh/sshd_config"
#5.2.22 Ensure SSH MaxStartups is configured (Scored)
add_parameter "maxstartups " "10:30:60" "/etc/ssh/sshd_config"
#5.2.23 Ensure SSH MaxSessions is set to 4 or less (Scored)
add_parameter "MaxSessions " 4 "/etc/ssh/sshd_config"
#5.3 Configure PAM
apt-get install libpam0g-dev
#5.3.1 Ensure password creation requirements are configured (Scored)
sed -i "/^# milen/ c milen = 14" /etc/security/pwquality.conf
sed -i "/^# dcredit/ c dcredit = -1" /etc/security/pwquality.conf
sed -i "/^# ucredit/ c ucredit = -1" /etc/security/pwquality.conf
sed -i "/^# ocredit/ c ocredit = -1" /etc/security/pwquality.conf
sed -i "/^# lcredit/ c lcredit = -1" /etc/security/pwquality.conf
#5.3.2 Ensure lockout for failed password attempts is configured (Not Scored)
#5.3.3 Ensure password reuse is limited (Not Scored)
#5.3.4 Ensure password hashing algorithm is SHA-512 (Not Scored)
#5.4 User Accounts and Environment
#5.4.1 Set Shadow Password Suite Parameters
#5.4.1.1 Ensure password expiration is 365 days or less (Scored)
add_parameter "PASS_MAX_DAYS " 365 "/etc/login.defs"
#5.4.1.2 Ensure minimum days between password changes is 7 or more (Scored)
add_parameter "PASS_MIN_DAYS " 7 "/etc/login.defs"
#5.4.1.3 Ensure password expiration warning days is 7 or more (Scored)
add_parameter "PASS_WARN_AGE " 7 "/etc/login.defs"
#5.4.1.4 Ensure inactive password lock is 30 days or less (Scored)
useradd -D -f 30
#5.4.1.5 Ensure all users last password change date is in the past (Scored)
#5.4.2 Ensure system accounts are secured (Scored)
#5.4.3 Ensure default group for the root account is GID 0 (Scored)
usermod -g 0 root
#5.4.4 Ensure default user umask is 027 or more restrictive (Scored)
if ! grep "^umask 027" /etc/bash.bashrc;then
	echo "umask 027" >> /etc/bash.bashrc
	umask 027
fi
#5.4.5 Ensure default user shell timeout is 900 seconds or less (Scored)
if ! grep "^TMOUT" /etc/bash.bashrc; then
	echo "TMOUT=900" >> /etc/bash.bashrc
fi
#5.5 Ensure root login is restricted to system console (Not Scored)
#5.6 Ensure access to the su command is restricted (Scored)
echo "auth required pam_wheel.so use_uid" >> /etc/pam.d/su

#============================ 6 System Maintenance ================================
#6.1 System File Permissions
#6.1.1 Audit system file permissions (Not Scored)
#6.1.2 Ensure permissions on /etc/passwd are configured (Scored)
chown root:root /etc/passwd
chmod 644 /etc/passwd
#6.1.3 Ensure permissions on /etc/shadow are configured (Scored)
chown root:root /etc/shadow
chown root:shadow /etc/shadow
chmod o-rwx,g-wx /etc/shadow
#6.1.4 Ensure permissions on /etc/group are configured (Scored)
chown root:root /etc/group
chmod 644 /etc/group
#6.1.5 Ensure permissions on /etc/gshadow are configured (Scored)
chown root:root /etc/gshadow
chown root:shadow /etc/gshadow
chmod o-rwx,g-rw /etc/gshadow
#6.1.6 Ensure permissions on /etc/passwd- are configured (Scored)
chown root:root /etc/passwd-
chmod u-x,go-rwx /etc/passwd-
#6.1.7 Ensure permissions on /etc/shadow- are configured (Scored)
chown root:root /etc/shadow-
chown root:shadow /etc/shadow-
chmod o-rwx,g-rw /etc/shadow-
#6.1.8 Ensure permissions on /etc/group- are configured (Scored)
chown root:root /etc/group-
chmod u-x,go-wx /etc/group-
#6.1.9 Ensure permissions on /etc/gshadow- are configured (Scored)
chown root:root /etc/gshadow-
chown root:shadow /etc/gshadow-
chmod o-rwx,g-rw /etc/gshadow-
#6.1.10 Ensure no world writable files exist (Scored)
wwf=$(find / -type f -perm -writable 2>/dev/null)
if [ -n "$wwf" ]; then
	for file in $wwf; do
		chmod -w "$file"
	done
fi
#6.1.11 Ensure no unowned files or directories exist (Scored)
unownedfile=$(find / -type f -nouser 2>/dev/null)
unownedDir=$(find / -type d -nouser 2>/dev/null)
if [ -n "$unownedfile" ] || [ -n "$unownedDir" ]; then
	for file in $unownedfile; do
		chown root:root "$file"
	done
	for dir in $unownedfile; do
		chown root:root "$dir"
	done
fi
#6.1.12 Ensure no ungrouped files or directories exist (Scored)
ungroupedfile=$(find / -type f -nogroup 2>/dev/null)
ungroupedDir=$(find / -type d -nogroup 2>/dev/null)
if [ -n "$ungroupedfile" ] || [ -n "$ungroupedDir" ]; then
	for file in $unownedfile; do
		chgrp root "$file"
	done
	for dir in $unownedfile; do
		chgrp root "$dir"
	done
fi
#6.1.13 Audit SUID executables (Not Scored)
#6.1.14 Audit SGID executables (Not Scored)
#6.2 User and Group Settings
#6.2.1 Ensure password fields are not empty (Scored)
userlock=$(awk -F: '($2 == "" ) { print $1 " does not have a password "}' /etc/shadow)
if [ -n "$userlock" ]; then
	echo "Because the user '$userlock' does not have a password, it will be locked!";
	passwd -l "$userlock"
fi
#6.2.2Ensure no legacy "+" entries exist in /etc/passwd (Scored)
sed -i "s/+//g" /etc/passwd
#6.2.3 Ensure no legacy "+" entries exist in /etc/shadow (Scored)
sed -i "s/+//g" /etc/shadow
#6.2.4 Ensure no legacy "+" entries exist in /etc/group (Scored)
sed -i "s/+//g" /etc/group
#6.2.5 Ensure root is the only UID 0 account (Scored)
userR=$(awk -F: '($3 == 0) { print $1 }' /etc/passwd)
if [ $userR != "root" ]; then
	userdel -r "$userR"
fi
#6.2.6 Ensure root PATH Integrity (Scored)
#6.2.7 Ensure all users' home directories exist (Scored)
#6.2.8 Ensure users' home directories permissions are 750 or more restrictive (Scored)
#6.2.9 Ensure users own their home directories (Scored)
#6.2.10 Ensure users' dot files are not group or world writable (Scored)
users=$(cut -d: -f1 /etc/passwd)
for user in $users; do
	dir="/home/$user"
	if [ ! -d "$dir" ]; then
		mkdir -p "$dir"
		chmod 750 "$dir"
		chown -R "$user:$user" "$dir"
	else 
		dot_files=$(find "$dir" -maxdepth 1 -name '.*')
		for file in $dot_files; do
			if [ -w "$file" ] && [ ! -h "$file" ]; then
				chmod go-w "$dir"
			fi
		done
	fi
done
#6.2.11 Ensure no users have .forward files (Scored)
rm_file ".forward"
#6.2.12 Ensure no users have .netrc files (Scored)
rm_file "netrc"
#6.2.13 Ensure users' .netrc Files are not group or world accessible (Scored)
#6.2.14 Ensure no users have .rhosts files (Scored)
rm_file ".rhosts"
#6.2.15 Ensure all groups in /etc/passwd exist in /etc/group (Scored)
#6.2.16 Ensure no duplicate UIDs exist (Scored)
#6.2.17 Ensure no duplicate GIDs exist (Scored)
#6.2.18 Ensure no duplicate user names exist (Scored)
#6.2.19 Ensure no duplicate group names exist (Scored)
#6.2.20 Ensure shadow group is empty (Scored)

#================================= 3 Network Configuration ================================
#3.1.1 Ensure Ip forwarding is disabled (Scored)
set_directive "net.ipv4.ip_forward" 0 "/etc/sysctl.conf"
set_directive "net.ipv6.conf.all.forwarding" 0 "/etc/sysctl.conf"
sysctl -w net.ipv4.ip_forward=0
sysctl -w net.ipv6.all.forwarding=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1
#3.1.2 Ensure packet redirect sending is disabled (Scored)
set_directive "net.ipv4.conf.all.send_redirects" 0 "/etc/sysctl.conf"
set_directive "net.ipv6.conf.default.send_redirects" 0 "/etc/sysctl.conf"
sysctl -w net.ipv4.conf.all.send_redirects=0
sysctl -w net.ipv4.conf.default.send_redirects=0
sysctl -w net.ipv4.route.flush=1
#3.2 Network parameters (Host and Router)
#3.2.1 Ensure source routed packets are not accepted (Scored)
set_directive "net.ipv4.conf.all.accept_source_route" 0 "/etc/sysctl.conf"
set_directive "net.ipv4.conf.default.accept_source_route" 0 "/etc/sysctl.conf"
set_directive "net.ipv6.conf.all.accept_source_route" 0 "/etc/sysctl.conf"
set_directive "net.ipv4.conf.default.accept_source_route" 0 "/etc/sysctl.conf"
sysctl -w net.ipv4.conf.all.accept_source_route=0
sysctl -w net.ipv4.conf.default.accept_source_route=0
sysctl -w net.ipv6.conf.all.accept_source_route=0
sysctl -w net.ipv6.conf.default.accept_source_route=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1
#3.2.2 Ensure ICMP redirects are not accepted (Scored)
set_directive "net.ipv4.conf.all.accept_redirects" 0 "/etc/sysctl.conf"
set_directive "net.ipv4.conf.default.accept_redirects" 0 "/etc/sysctl.conf"
set_directive "net.ipv6.conf.all.accept_redirects" 0 "/etc/sysctl.conf"
set_directive "net.ipv6.conf.default.accept_redirects" 0 "/etc/sysctl.conf"
sysctl -w net.ipv4.conf.all.accept_redirects=0
sysctl -w net.ipv4.conf.default.accept_redirects=0
sysctl -w net.ipv6.conf.all.accept_redirects=0
sysctl -w net.ipv6.conf.default.accept_redirects=0
sysctl -w net.ipv4.route.flush=1
sysctl -w net.ipv6.route.flush=1
#3.2.3 Ensure secure ICMP redirects are not accepted (Scored)
set_directive "net.ipv4.conf.all.secure_redirects" 0 "/etc/sysctl.conf"
set_directive "net.ipv4.conf.all.secure_redirects" 0 "/etc/sysctl.conf"
sysctl -w net.ipv4.conf.all.secure_redirects=0
sysctl -w net.ipv6.conf.default.secure_redirects=0
sysctl -w net.ipv4.route.flush=1
#3.2.4 Ensure suspicious packets are logged (Scored)
set_directive "net.ipv4.conf.all.log_martians" 1 "/etc/sysctl.conf"
set_directive "net.ipv4.conf.default.log_martains" 1 "/etc/sysctl.conf"
sysctl -w net.ipv4.conf.all.log_martains=1
sysctl -w net.ipv6.conf.default.log_martains=1
sysctl -w net.ipv4.route.flush=1
#3.2.5 Ensure broadcast ICMP requests are ignored (Scored)
set_directive "net.ipv4.icmp_echo_ignore_broadcasts" 1 "/etc/sysctl.conf"
sysctl -w net.ipv4.icmp_echo_ignore_broadcasts=1
sysctl -w net.ipv4.route.flush=1
#3.2.6 Ensure bogus ICMP responses are ignored (Scored)
set_directive "net.ipv4.icmp_ignore_bogus_error_responses" 1 "/etc/sysctl.conf"
sysctl -w net.ipv4.icmp_ignore_bogus_error_reponses=1
sysctl -w net.ipv4.route.flush=1
#3.2.7 Ensure Reverse Path Filtering is enabled (Scored)
set_directive "net.ipv4.conf.all.rp_filter" 1 "/etc/sysctl.conf"
set_directive "net.ipv4.conf.default.rp_filter" 1 "/etc/sysctl.conf"
sysctl -w net.ipv4.conf.all.rp_filter=1
sysctl -w net.ipv4.conf.default.rp_filter=1
sysctl -w net.ipv4.route.flush=1
#3.2.8 Ensure TCP SYN Cookies is enabled (Scored)
set_directive "net.ipv4.tcp_syncookies" 1 "/etc/sysctl.conf"
sysctl -w net.ipv4.tcp_syncookies=1
sysctl -w net.ipv4.route.flush=1
#3.2.9 Ensure IPv6 router advertisements are not accepted (Scored)
set_directive "net.ipv6.conf.all.accept_ra" 0 "/etc/sysctl.conf"
set_directive "net.ipv6.conf.all.accept_ra" 0 "/etc/sysctl.conf"
sysctl -w net.ipv4.conf.all.accept_ra=0
sysctl -w net.ipv6.conf.default.accept_ra=0
sysctl -w net.ipv4.route.flush=1
#3.3 TCP wrappers
#3.3.1 Ensure TCP Wrappers is installed (Not Scored)
apt-get install tcpd
#3.3.2 Ensure /etc/hosts.allow is configured (Not Scored)
if ! grep "^192.168" /etc/hosts.allow; then
	read -s -p "Enter Hosts.allow: " hosts
	echo "ALL:$hosts" >> /etc/hosts.allow
fi
#3.3.3 Ensure /etc/hosts.deny is configured (Not Scored)
if ! grep "ALL:ALL" /etc/hosts.deny; then
	echo "ALL:ALL" >> /etc/hosts.deny
fi
#3.3.4 Ensure permissions on /etc/hosts.allow are configured (Scored)
chown root:root /etc/hosts.allow
chmod 644 /etc/hosts.allow
#3.3.5 Ensure permissions on /etc/hosts.deny are configured (Scored)
chown root:root /etc/hosts.deny
chmod 644 /etc/hosts.deny
#3.4 Uncommon Network Protocols
#3.4.1 Ensure DCCP is disabled (Scored)
set_mount_fs "dccp"
#3.4.2 Ensure SCTP is disabled (Scored)
set_mount_fs "sctp"
#3.4.3 Ensure RDS is disabled (Scored)
set_mount_fs "rds"
#3.4.4 Ensure TIPC is disabled (Scored)
set_mount_fs "tipc"
#3.5 Firewall configuration
#3.5.1 Configure IPv6 ip6tables
#3.5.1.1 Ensure IPv6 default deny firewall policy (Scored)
ip6tables -P INPUT DROP
ip6tables -P OUTPUT DROP
ip6tables -P FORWARD DROP
#3.5.1.2 Ensure IPv6 loopback traffic is configured (Scored)
ip6tables -A INPUT -i lo -j ACCEPT
ip6tables -A OUTPUT -o lo -j ACCEPT
ip6tables -A INPUT -s ::1 -j ACCEPT
#3.5.1.3 Ensure IPv6 outbound and established connections are configured (Not Scored)
#3.5.1.4 Ensure IPv6 firewall rules exist for all open ports (Not Scored)
#3.5.2 Configure IPv4 iptables
#3.5.2.3 Ensure outbound and established connections are configured (Not Scored)
#3.5.2.4 Ensure firewall rules exist for all open ports (Scored)
#3.5.3 Ensure iptables is installed (Scored)
apt-get -y install iptables
#3.5.2.1 Ensure default deny firewall policy (Scored)
iptables -P INPUT DROP
iptables -P OUTPUT DROP
iptables -P FORWARD DROP
#3.5.2.2 Ensure loopback traffic is configured (Scored)
iptables -A INPUT -i lo -j ACCEPT
iptables -A OUTPUT -o lo -j ACCEPT
iptables -A INPUT -s 127.0.0.0/8 -j DROP
#3.6 Ensure wireless interfaces are disabled (Not Scored)
#3.7 Disable IPv6 (Not Scored)

############################################################
#Records the root user's command line execution history
ehco "
HISTFILESIZE=1000000
HISTSIZE=1000000
HISTTIMEFORMAT='%F %T '
PROMPT_COMMAND='history -a'
" >> /root/.bashrc
echo "RESTART SYSTEM"
sleep 10
shutdown -r now
