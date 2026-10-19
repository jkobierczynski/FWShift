#!/bin/sh
# FWShift lab: the first boot of a test host (lab/README.md). Written into the user data by lab/labrun.py.
# It routes what the test address sends through the test interface, and starts the probe's answers on that address.
# The management interface (with the default route and SSH from your address) stays as it is.
set -eu
TEST_IP='${test_ip}'
TEST_GW='${test_gw}'
TEST_NET='${test_net}'
SUBNET_VIA_GW='${subnet_via_gw}'
LAB_NET='10.20.0.0/16'
mkdir -p /opt/fwlab
echo '${probe_b64}' | base64 -d | gunzip > /opt/fwlab/probe.py
chmod 755 /opt/fwlab/probe.py

# The test interface may be attached after boot (AWS): wait for its address. The cloud gives it by DHCP; if that has not
# happened after two minutes, the address goes on an interface that has none (as /32: the routes below are explicit).
dev=''
i=0
while [ $i -lt 120 ]; do
  dev=$(ip -o -4 addr show | awk -v ip="$TEST_IP" '{ split($4, a, "/"); if (a[1] == ip) { print $2; exit } }')
  [ -n "$dev" ] && break
  if [ $i -ge 24 ]; then
    for link in $(ip -o link show | awk -F': ' '{ print $2 }' | cut -d@ -f1); do
      [ "$link" = lo ] && continue
      if [ -z "$(ip -o -4 addr show dev "$link")" ]; then
        echo "fwlab: no DHCP address for $TEST_IP yet; setting it on $link" >&2
        ip link set dev "$link" up && ip addr add "$TEST_IP/32" dev "$link" || true
        break
      fi
    done
  fi
  i=$((i + 1))
  sleep 5
done
if [ -z "$dev" ]; then
  echo "fwlab: no interface has $TEST_IP" >&2
  exit 1
fi

# Replies leave by the interface they came in on: loose reverse-path checks, and a table for the test address.
sysctl -qw net.ipv4.conf.all.rp_filter=2 "net.ipv4.conf.$dev.rp_filter=2" || true
if [ "$SUBNET_VIA_GW" = yes ]; then
  # Google Cloud: the interface has a /32, and the network answers through its gateway, also for the own subnet.
  ip route replace "$TEST_GW" dev "$dev" src "$TEST_IP" table 120
  ip route replace "$TEST_NET" via "$TEST_GW" dev "$dev" src "$TEST_IP" table 120
else
  ip route replace "$TEST_NET" dev "$dev" src "$TEST_IP" table 120
fi
ip route replace "$LAB_NET" via "$TEST_GW" dev "$dev" table 120
ip rule del from "$TEST_IP" lookup 120 2>/dev/null || true
ip rule add from "$TEST_IP" lookup 120 priority 120

# The answers: every TCP and UDP port of the plan on the test address (sshd keeps answering on 22).
cat > /etc/systemd/system/fwlab-probe.service <<EOF
[Unit]
Description=FWShift lab probe (answers)
After=network-online.target

[Service]
ExecStart=/usr/bin/env python3 /opt/fwlab/probe.py serve --bind $TEST_IP --tcp ${tcp_ports} --udp ${udp_ports}
Restart=always

[Install]
WantedBy=multi-user.target
EOF
if command -v systemctl >/dev/null 2>&1; then
  systemctl daemon-reload && systemctl enable --now fwlab-probe.service
else
  nohup python3 /opt/fwlab/probe.py serve --bind "$TEST_IP" --tcp ${tcp_ports} --udp ${udp_ports} >/var/log/fwlab-probe.log 2>&1 &
fi
echo "fwlab: $TEST_IP on $dev, via $TEST_GW"
