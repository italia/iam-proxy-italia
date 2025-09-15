#!/bin/bash

# netstat -taunp
# ss -s

# put them in /etc/sysctl or /etc/sysctl.d#!/bin/bash
net.ipv4.ip_local_port_range=1025 65435

net.ipv4.tcp_mtu_probing=1
net.ipv4.tcp_window_scaling=1
net.ipv4.tcp_adv_win_scale=1
net.ipv4.tcp_low_latency=1

net.ipv4.tcp_timestamps=0 
net.ipv4.tcp_tw_reuse=1 
net.ipv4.tcp_tw_recycle=1 
net.ipv4.tcp_keepalive_time=1800 

net.ipv4.tcp_rmem=4096 87380 8388608
net.ipv4.tcp_wmem=4096 87380 8388608

net.ipv4.tcp_fin_timeout=10

net.core.somaxconn=10000
net.ipv4.tcp_max_syn_backlog=10000

# If the option is set, we conform to RFC 1337 and drop RST packets, preventing TIME-WAIT Assassination
net.ipv4.tcp_rfc1337=1

net.ipv4.tcp_max_tw_buckets=1440000

# 0 tells the kernel to avoid swapping processes out of physical memory
# for as long as possible
# 100 tells the kernel to aggressively swap processes out of physical memory
# and move them to swap cache
vm.swappiness=0

# CoDel works by looking at the packets at the head of the queue — those which have been through the entire queue and are about to be transmitted.
# If they have been in the queue for too long, they are simply dropped
net.core.default_qdisc=fq_codel

# disables RFC 2861 behavior and time out the congestion window without an idle period
net.ipv4.tcp_slow_start_after_idle=0

# then
# sysctl -p
