# server performance
# man tcp
sysctl -w net.ipv4.tcp_fin_timeout = 20
sysctl -w net.ipv4.ip_local_port_range="1024 65535"

# the max number of connection requests that can be queued for any given listening socket, Limit of socket listen() backlog
sysctl -w net.core.somaxconn=1000
sysctl -w net.ipv4.tcp_max_syn_backlog=1000

# read and write mem
net.ipv4.tcp_rmem = 4096 12582912 16777216
net.ipv4.tcp_wmem = 4096 12582912 16777216

# CoDel works by looking at the packets at the head of the queue — those which have been through the entire queue and are about to be transmitted.
# If they have been in the queue for too long, they are simply dropped
sysctl -w net.core.default_qdisc=fq_codel

# disables RFC 2861 behavior and time out the congestion window without an idle period
sysctl -w net.ipv4.tcp_slow_start_after_idle=0

# Allow to reuse TIME_WAIT sockets for new connections when it is safe from protocol viewpoint.
sysctl -w net.ipv4.tcp_tw_reuse=1

# makes things permanent
# sysctl -p
#
