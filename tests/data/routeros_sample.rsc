# 2026-10-13 09:30:02 by RouterOS 7.16.2
# software id = TEST-0023
#
# model = RB5009UG+S+
/interface bridge
add comment=defconf name=bridge-lan port-cost-mode=short
/interface vlan
add interface=ether3 name=vlan20-dmz vlan-id=20
add interface=ether3 name=vlan30-guest vlan-id=30
/interface list
add comment=defconf name=WAN
add comment=defconf name=LAN
add name=DMZ
add name=GUEST
add include=LAN,DMZ name=INSIDE
/interface bridge port
add bridge=bridge-lan interface=ether2
add bridge=bridge-lan interface=ether4
/interface list member
add comment=defconf interface=bridge-lan list=LAN
add comment=defconf interface=ether1 list=WAN
add interface=vlan20-dmz list=DMZ
add interface=vlan30-guest list=GUEST
/ip address
add address=192.168.10.1/24 comment=defconf interface=bridge-lan \
    network=192.168.10.0
add address=172.16.20.1/24 interface=vlan20-dmz network=172.16.20.0
add address=172.16.30.1/24 interface=vlan30-guest network=172.16.30.0
add address=203.0.113.2/29 interface=ether1 network=203.0.113.0
/ip firewall address-list
add address=172.16.20.10 comment="web server" list=dmz-web
add address=172.16.20.11 list=dmz-web
add address=192.168.10.50-192.168.10.59 comment="admin PCs" list=admins
add address=198.51.100.0/24 list=partners
add address=192.0.2.66 disabled=yes list=partners
add address=updates.example.com \
    comment="package mirror, resolved by the router" list=mirrors
add address=192.0.2.80 list=mirrors
/ip firewall filter
add action=accept chain=input \
    comment="defconf: accept established,related,untracked" \
    connection-state=established,related,untracked
add action=drop chain=input comment="defconf: drop all not coming from LAN" \
    in-interface-list=!LAN
add action=accept chain=forward comment="defconf: accept in ipsec policy" \
    ipsec-policy=in,ipsec
add action=fasttrack-connection chain=forward comment="defconf: fasttrack" \
    connection-state=established,related hw-offload=yes
add action=accept chain=forward \
    comment="defconf: accept established,related, untracked" \
    connection-state=established,related,untracked
add action=drop chain=forward comment="defconf: drop invalid" \
    connection-state=invalid
add action=drop chain=forward comment="banned scanners" \
    src-address-list=scanners
add action=jump chain=forward comment="to the DMZ" jump-target=to-dmz \
    out-interface-list=DMZ
add action=accept chain=forward comment="LAN to the package mirrors" \
    dst-address-list=mirrors dst-port=80,443 in-interface-list=LAN protocol=tcp
add action=reject chain=forward comment="no other web from guests" \
    dst-port=80,443 in-interface-list=GUEST protocol=tcp reject-with=tcp-reset
add action=accept chain=forward comment="guest DNS, either port" \
    in-interface-list=GUEST out-interface-list=WAN port=53 protocol=udp
add action=log chain=forward in-interface-list=GUEST log-prefix=GUEST-OUT \
    out-interface-list=WAN
add action=accept chain=forward comment="guests to the internet" \
    in-interface-list=GUEST out-interface-list=WAN
add action=accept chain=forward comment="office hours for staff" \
    in-interface-list=LAN out-interface-list=WAN src-address=192.168.10.0/25 \
    time=8h-18h,mon,tue,wed,thu,fri
add action=drop chain=forward comment="no guests elsewhere" \
    in-interface-list=GUEST log=yes log-prefix=GUEST-DROP
add action=add-src-to-address-list address-list=scanners \
    address-list-timeout=1d chain=forward dst-port=23 in-interface-list=WAN \
    protocol=tcp
add action=drop chain=forward \
    comment="defconf: drop all from WAN not DSTNATed" \
    connection-nat-state=!dstnat connection-state=new in-interface-list=WAN
add action=return chain=to-dmz comment="ssh only from the admins" dst-port=22 \
    protocol=tcp src-address-list=!admins
add action=accept chain=to-dmz comment="ssh from the admins" \
    dst-address-list=dmz-web dst-port=22 protocol=tcp
add action=accept chain=to-dmz comment="web for everyone" \
    dst-address-list=dmz-web dst-port=80,443,8000-8080 protocol=tcp
add action=accept chain=to-dmz comment="ping \"echo\" only" icmp-options=8:0 \
    protocol=icmp
add action=accept chain=to-dmz comment="old partner access" disabled=yes \
    src-address-list=partners
add action=reject chain=to-dmz comment="nothing but TCP" protocol=!tcp \
    reject-with=icmp-admin-prohibited
add action=drop chain=to-dmz comment="rest of the DMZ" \
    dst-address=!172.16.20.0/25
/ip firewall nat
add action=masquerade chain=srcnat comment="defconf: masquerade" \
    ipsec-policy=out,none out-interface-list=WAN
add action=dst-nat chain=dstnat comment="publish web" dst-address=203.0.113.3 \
    dst-port=8443 in-interface-list=WAN protocol=tcp to-addresses=172.16.20.10 \
    to-ports=443
add action=dst-nat chain=dstnat comment="publish mail" dst-address=203.0.113.4 \
    dst-port=25 in-interface-list=WAN protocol=tcp to-addresses=172.16.20.11
/ip firewall mangle
add action=mark-connection chain=prerouting in-interface-list=GUEST \
    new-connection-mark=guest passthrough=yes
/ipv6 firewall address-list
add address=2001:db8:10::/64 list=lan6
add address=2001:db8:99::/48 comment="partner\_net" list=partners
/ipv6 firewall filter
add action=accept chain=forward connection-state=established,related,untracked
add action=drop chain=forward connection-state=invalid
add action=accept chain=forward comment="ICMPv6 echo" icmp-options=128:0-255 \
    protocol=icmpv6
add action=accept chain=forward \
    comment="the partners reach the web servers of the LAN by HTTPS and nothing\
    \_else" dst-address-list=lan6 dst-port=443 protocol=tcp \
    src-address-list=partners
add action=drop chain=forward \
    comment="drop everything else not coming from LAN" in-interface-list=!LAN
