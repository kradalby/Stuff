#!/bin/sh
#------------------------------------------------------------------------------
#
# File: SIG-antiDDoS.sh
#
# Compiler: Ruslan Abuzant <ruslan@abuzant.com>
#           PS> Collected From Lots Of Sources
#           PS> Credits: Real Authors (no idea)
#
# URL: http://www.liteforex.org/
#
# License: GNU GPL (version 2, or any later version).
#
# Configuration.
#------------------------------------------------------------------------------

# For debugging use iptables -v.
IPTABLES="/sbin/iptables"
IP6TABLES="/sbin/ip6tables"
MODPROBE="/sbin/modprobe"
RMMOD="/sbin/rmmod"
ARP="/usr/sbin/arp"
WANIF="eth0"
LANIF="eth1"

#HOSTS
BORG="10.0.0.1"
DEVORE="10.0.0.2"
FINA="10.0.0.3"
ENERA="10.0.0.4"

#PORTS
CS16="16000:18000"
TF2="30000:31000"
CSS="25000:27004"
CSS2="27006:28000"
CSGO="40000:41000"


# Logging options.
#------------------------------------------------------------------------------
LOG_PREFIX="firew:"
LOG="LOG --log-level debug --log-tcp-sequence --log-tcp-options"
LOG="$LOG --log-ip-options"


# Defaults for rate limiting
#------------------------------------------------------------------------------
RLIMIT="-m limit --limit 3/s --limit-burst 8"



# Load required kernel modules
#------------------------------------------------------------------------------
$MODPROBE ip_conntrack_ftp
$MODPROBE ip_conntrack_irc


# Mitigate ARP spoofing/poisoning and similar attacks.
#------------------------------------------------------------------------------
# Hardcode static ARP cache entries here
# $ARP -s IP-ADDRESS MAC-ADDRESS


# Kernel configuration.
#------------------------------------------------------------------------------

# Disable IP forwarding.
# On => Off = (reset)
echo 1 > /proc/sys/net/ipv4/ip_forward

# Enable IP spoofing protection
for i in /proc/sys/net/ipv4/conf/*/rp_filter; do echo 1 > $i; done

# Protect against SYN flood attacks
echo 1 > /proc/sys/net/ipv4/tcp_syncookies

# Ignore all incoming ICMP echo requests
echo 0 > /proc/sys/net/ipv4/icmp_echo_ignore_all

# Ignore ICMP echo requests to broadcast
echo 1 > /proc/sys/net/ipv4/icmp_echo_ignore_broadcasts

# Log packets with impossible addresses.
for i in /proc/sys/net/ipv4/conf/*/log_martians; do echo 1 > $i; done

# Don't log invalid responses to broadcast
echo 1 > /proc/sys/net/ipv4/icmp_ignore_bogus_error_responses

# Don't accept or send ICMP redirects.
for i in /proc/sys/net/ipv4/conf/*/accept_redirects; do echo 0 > $i; done
for i in /proc/sys/net/ipv4/conf/*/send_redirects; do echo 0 > $i; done

# Don't accept source routed packets.
for i in /proc/sys/net/ipv4/conf/*/accept_source_route; do echo 0 > $i; done

# Disable proxy_arp.
for i in /proc/sys/net/ipv4/conf/*/proxy_arp; do echo 0 > $i; done

# Enable secure redirects, i.e. only accept ICMP redirects for gateways
# Helps against MITM attacks.
for i in /proc/sys/net/ipv4/conf/*/secure_redirects; do echo 1 > $i; done

# Disable bootp_relay
for i in /proc/sys/net/ipv4/conf/*/bootp_relay; do echo 0 > $i; done

# Default policies.
#------------------------------------------------------------------------------

# Drop everything by default.
$IPTABLES -P INPUT DROP
#$IPTABLES -P FORWARD DROP
#$IPTABLES -P OUTPUT DROP

# Set the nat/mangle/raw tables' chains to ACCEPT
$IPTABLES -t nat -P PREROUTING ACCEPT
$IPTABLES -t nat -P OUTPUT ACCEPT
$IPTABLES -t nat -P POSTROUTING ACCEPT

$IPTABLES -t mangle -P PREROUTING ACCEPT
$IPTABLES -t mangle -P INPUT ACCEPT
$IPTABLES -t mangle -P FORWARD ACCEPT
$IPTABLES -t mangle -P OUTPUT ACCEPT
$IPTABLES -t mangle -P POSTROUTING ACCEPT


# Cleanup.
#------------------------------------------------------------------------------

# Delete all
$IPTABLES -F
$IPTABLES -t nat -F
$IPTABLES -t mangle -F

# Delete all
$IPTABLES -X
$IPTABLES -t nat -X
$IPTABLES -t mangle -X

# Zero all packets and counters.
$IPTABLES -Z
$IPTABLES -t nat -Z
$IPTABLES -t mangle -Z


# Completely disable IPv6.
#------------------------------------------------------------------------------

#TODO FIX IPv6


# Custom user-defined chains.
#------------------------------------------------------------------------------

# LOG packets, then ACCEPT.
$IPTABLES -N ACCEPTLOG
$IPTABLES -A ACCEPTLOG -j $LOG $RLIMIT --log-prefix "$LOG_PREFIX ACCEPT "
$IPTABLES -A ACCEPTLOG -j ACCEPT

# LOG packets, then DROP.
$IPTABLES -N DROPLOG
$IPTABLES -A DROPLOG -j $LOG $RLIMIT --log-prefix "$LOG_PREFIX DROP "
$IPTABLES -A DROPLOG -j DROP

# LOG packets, then REJECT.
# TCP packets are rejected with a TCP reset.
$IPTABLES -N REJECTLOG
$IPTABLES -A REJECTLOG -j $LOG $RLIMIT --log-prefix "$LOG_PREFIX REJECT "
$IPTABLES -A REJECTLOG -p tcp -j REJECT --reject-with tcp-reset
$IPTABLES -A REJECTLOG -j REJECT

# Only allows RELATED ICMP types
# (destination-unreachable, time-exceeded, and parameter-problem).
# TODO: Rate-limit this traffic?
# TODO: Allow fragmentation-needed?
# TODO: Test.
$IPTABLES -N RELATED_ICMP
$IPTABLES -A RELATED_ICMP -p icmp --icmp-type destination-unreachable -j ACCEPT
$IPTABLES -A RELATED_ICMP -p icmp --icmp-type time-exceeded -j ACCEPT
$IPTABLES -A RELATED_ICMP -p icmp --icmp-type parameter-problem -j ACCEPT
$IPTABLES -A RELATED_ICMP -j DROPLOG

# Make It Even Harder To Multi-PING
$IPTABLES  -A INPUT -p icmp -m limit --limit 1/s --limit-burst 2 -j ACCEPT
$IPTABLES  -A INPUT -p icmp -m limit --limit 1/s --limit-burst 2 -j $LOG --log-prefix "$LOG_PREFIX PING-DROP:"
$IPTABLES  -A INPUT -p icmp -j DROP
$IPTABLES  -A OUTPUT -p icmp -j ACCEPT

# Only allow the minimally required/recommended parts of ICMP. Block the rest.
#------------------------------------------------------------------------------

# TODO: This section needs a lot of testing!

# First, drop all fragmented ICMP packets (almost always malicious).
$IPTABLES -A INPUT -p icmp --fragment -j DROPLOG
$IPTABLES -A OUTPUT -p icmp --fragment -j DROPLOG
$IPTABLES -A FORWARD -p icmp --fragment -j DROPLOG

# Allow all ESTABLISHED ICMP traffic.
$IPTABLES -A INPUT -p icmp -m state --state ESTABLISHED -j ACCEPT $RLIMIT
$IPTABLES -A OUTPUT -p icmp -m state --state ESTABLISHED -j ACCEPT $RLIMIT

# Allow some parts of the RELATED ICMP traffic, block the rest.
$IPTABLES -A INPUT -p icmp -m state --state RELATED -j RELATED_ICMP $RLIMIT
$IPTABLES -A OUTPUT -p icmp -m state --state RELATED -j RELATED_ICMP $RLIMIT

# Allow incoming ICMP echo requests (ping), but only rate-limited.
$IPTABLES -A INPUT -p icmp --icmp-type echo-request -j ACCEPT $RLIMIT

# Allow outgoing ICMP echo requests (ping), but only rate-limited.
$IPTABLES -A OUTPUT -p icmp --icmp-type echo-request -j ACCEPT $RLIMIT

# Allow incoming ICMP type 3, but only rate-limited.
$IPTABLES -A INPUT -p icmp --icmp-type 3 -j ACCEPT $RLIMIT

# Allow outgoing ICMP type 3, but only rate-limited.
$IPTABLES -A OUTPUT -p icmp --icmp-type 3 -j ACCEPT $RLIMIT

# Drop any other ICMP traffic.
$IPTABLES -A INPUT -p icmp -j DROPLOG
$IPTABLES -A OUTPUT -p icmp -j DROPLOG
$IPTABLES -A FORWARD -p icmp -j DROPLOG

# Selectively allow certain special types of traffic.
#------------------------------------------------------------------------------

# Allow loopback interface to do anything.
$IPTABLES -A INPUT -i lo -j ACCEPT
$IPTABLES -A OUTPUT -o lo -j ACCEPT

# Allow incoming connections related to existing allowed connections.
$IPTABLES -A INPUT -m state --state ESTABLISHED,RELATED -j ACCEPT

# Allow outgoing connections EXCEPT invalid
$IPTABLES -A OUTPUT -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT


# Miscellaneous.
#------------------------------------------------------------------------------

# We don't care about Milkosoft, Drop SMB/CIFS/etc..
$IPTABLES -A INPUT -p tcp -m multiport --dports 135,137,138,139,445,1433,1434 -j DROP
$IPTABLES -A INPUT -p udp -m multiport --dports 135,137,138,139,445,1433,1434 -j DROP

# Explicitly drop invalid incoming traffic
$IPTABLES -A INPUT -m state --state INVALID -j DROP

# Drop invalid outgoing traffic, too.
$IPTABLES -A OUTPUT -m state --state INVALID -j DROP

# If we would use NAT, INVALID packets would pass - BLOCK them anyways
$IPTABLES -A FORWARD -m state --state INVALID -j DROP

# PORT Scanners (stealth also)
$IPTABLES -A INPUT -m state --state NEW -p tcp --tcp-flags ALL ALL -j DROP
$IPTABLES -A INPUT -m state --state NEW -p tcp --tcp-flags ALL NONE -j DROP

# TODO: Some more anti-spoofing rules? For example:
# $IPTABLES -A INPUT -p tcp --tcp-flags ALL FIN,URG,PSH -j DROP
# $IPTABLES -A INPUT -p tcp --tcp-flags SYN,RST SYN,RST -j DROP
# $IPTABLES -A INPUT -p tcp --tcp-flags SYN,FIN SYN,FIN -j DROP
$IPTABLES -N SYN_FLOOD
$IPTABLES -A INPUT -p tcp --syn -j SYN_FLOOD
$IPTABLES -A SYN_FLOOD -m limit --limit 2/s --limit-burst 6 -j RETURN
$IPTABLES -A SYN_FLOOD -j DROP

# TODO: Block known-bad IPs (see http://www.dshield.org/top10.php).
# $IPTABLES -A INPUT -s INSERT-BAD-IP-HERE -j DROPLOG

# Reject spoofed packets
#-------------------------------------------------------------------------------
$IPTABLES -A INPUT -s 169.254.0.0/16 -j DROP
$IPTABLES -A INPUT -s 172.16.0.0/12 -j DROP
$IPTABLES -A INPUT -s 127.0.0.0/8 -j DROP

$IPTABLES -A INPUT -s 224.0.0.0/4 -j DROP
$IPTABLES -A INPUT -d 224.0.0.0/4 -j DROP
$IPTABLES -A INPUT -s 240.0.0.0/5 -j DROP
$IPTABLES -A INPUT -d 240.0.0.0/5 -j DROP
$IPTABLES -A INPUT -s 0.0.0.0/8 -j DROP
$IPTABLES -A INPUT -d 0.0.0.0/8 -j DROP
$IPTABLES -A INPUT -d 239.255.255.0/24 -j DROP
$IPTABLES -A INPUT -d 255.255.255.255 -j DROP


# SRCDS releated drop rules
#------------------------------------------------------------------------------
$IPTABLES -A INPUT -p udp -m multiport --dports 16000:45000 -m length --length 0:32 -j LOG --log-prefix "$LOG_PREFIX SRCDS-XSQUERY " --log-ip-options -m limit --limit 1/m --limit-burst 1
$IPTABLES -A INPUT -p udp -m multiport --dports 16000:45000 -m length --length 0:32 -j DROP


# Selectively allow certain inbound connections, block the rest.
#------------------------------------------------------------------------------

# Allow incoming HTTP requests.
$IPTABLES -A INPUT -m state --state NEW -p tcp --dport 80 -j ACCEPT

# Allow incoming SSH requests.
$IPTABLES -A INPUT -m state --state NEW -p tcp --dport 22 -j ACCEPT


# Portforwarding
#------------------------------------------------------------------------------

#SSH Borg
$IPTABLES -t nat -A PREROUTING -p tcp -i $WANIF --dport 21 -j DNAT --to-destination $BORG:22
$IPTABLES -A FORWARD -p tcp -d $BORG --dport 22 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

#SSH Devore
$IPTABLES -t nat -A PREROUTING -p tcp -i $WANIF --dport 22 -j DNAT --to-destination $DEVORE:22
$IPTABLES -A FORWARD -p tcp -d $DEVORE --dport 22 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

#SSH Fina
$IPTABLES -t nat -A PREROUTING -p tcp -i $WANIF --dport 23 -j DNAT --to-destination $FINA:22
$IPTABLES -A FORWARD -p tcp -d $FINA --dport 22 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

#SSH Enera
$IPTABLES -t nat -A PREROUTING -p tcp -i $WANIF --dport 24 -j DNAT --to-destination $ENERA:22
$IPTABLES -A FORWARD -p tcp -d $ENERA --dport 22 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

#MySQL Enera
$IPTABLES -t nat -A PREROUTING -p tcp -i $WANIF -s 31.24.131.151 --dport 56789 -j DNAT --to-destination $ENERA:3306
$IPTABLES -A FORWARD -p tcp -s 31.24.131.151 -d $ENERA --dport 3306 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

#SRCDS devore
$IPTABLES -t nat -A PREROUTING -p tcp -i $WANIF -m multiport --ports $CSS -j DNAT --to-destination $DEVORE
$IPTABLES -A FORWARD -p tcp -d $DEVORE --dport $CSS -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -t nat -A PREROUTING -p udp -i $WANIF -m multiport --ports $CSS -j DNAT --to-destination $DEVORE
$IPTABLES -A FORWARD -p udp -d $DEVORE --dport $CSS -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

#SRCDS2 devore
$IPTABLES -t nat -A PREROUTING -p tcp -i $WANIF -m multiport --ports $CSS2 -j DNAT --to-destination $DEVORE
$IPTABLES -A FORWARD -p tcp -d $DEVORE --dport $CSS2 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -t nat -A PREROUTING -p udp -i $WANIF -m multiport --ports $CSS2 -j DNAT --to-destination $DEVORE
$IPTABLES -A FORWARD -p udp -d $DEVORE --dport $CSS2 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

#SRCDS TF fina
$IPTABLES -t nat -A PREROUTING -p tcp -i $WANIF -m multiport --ports 30000:31000 -j DNAT --to-destination $FINA
$IPTABLES -A FORWARD -p tcp -d $FINA --dport 30000:31000 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -t nat -A PREROUTING -p udp -i $WANIF -m multiport --ports 30000:31000 -j DNAT --to-destination $FINA
$IPTABLES -A FORWARD -p udp -d $FINA --dport 30000:31000 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

#SRCDS GO fina
$IPTABLES -t nat -A PREROUTING -p tcp -i $WANIF -m multiport --ports 40000:40100 -j DNAT --to-destination $FINA
$IPTABLES -A FORWARD -p tcp -d $FINA --dport 40000:40100 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -t nat -A PREROUTING -p udp -i $WANIF -m multiport --ports 40000:40100 -j DNAT --to-destination $FINA
$IPTABLES -A FORWARD -p udp -d $FINA --dport 40000:40100 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

#HLDS fina
$IPTABLES -t nat -A PREROUTING -p udp -i $WANIF -m multiport --ports $CS16 -j DNAT --to-destination $FINA
$IPTABLES -A FORWARD -p udp -d $FINA --dport $CS16 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -t nat -A PREROUTING -p tcp -i $WANIF -m multiport --ports $CS16 -j DNAT --to-destination $FINA
$IPTABLES -A FORWARD -p tcp -d $FINA --dport $CS16 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

#Mosh Devore
$IPTABLES -t nat -A PREROUTING -p udp -i $WANIF -m multiport --ports 60000:60100 -j DNAT --to-destination $DEVORE
$IPTABLES -A FORWARD -p udp -d $DEVORE --dport 60000:60100 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

#Mosh Fina
$IPTABLES -t nat -A PREROUTING -p udp -i $WANIF -m multiport --ports 60101:60200 -j DNAT --to-destination $FINA
$IPTABLES -A FORWARD -p udp -d $FINA --dport 60101:60200 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT

#Mosh Enera
$IPTABLES -t nat -A PREROUTING -p udp -i $WANIF -m multiport --ports 60201:60300 -j DNAT --to-destination $ENERA
$IPTABLES -A FORWARD -p udp -d $ENERA --dport 60201:60300 -m state --state NEW,ESTABLISHED,RELATED -j ACCEPT


# NAT
#------------------------------------------------------------------------------
$IPTABLES -A FORWARD -i $WANIF -o $LANIF -m state --state ESTABLISHED,RELATED -j ACCEPT
$IPTABLES -A FORWARD -i $LANIF -o $WANIF -j ACCEPT
$IPTABLES -t nat -A POSTROUTING -o $WANIF -j MASQUERADE


# Explicitly log and reject everything else.
#------------------------------------------------------------------------------
# Use REJECT instead of REJECTLOG if you don't need/want logging.
$IPTABLES -A INPUT -j REJECTLOG
$IPTABLES -A OUTPUT -j REJECTLOG
$IPTABLES -A FORWARD -j REJECTLOG


    exit 0
