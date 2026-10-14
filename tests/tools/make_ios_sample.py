# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/ios_sample.cfg: a made-up branch router running IOS XE, as ``show running-config`` prints it.

Interface access lists (numbered and named, IPv4 and IPv6, inbound and outbound), object groups, the zone-based
policy firewall with a zone pair to the router itself, static and dynamic NAT. Every address is a documentation or
private address; nothing is taken from a real router.

    python3 tests/tools/make_ios_sample.py
"""

from __future__ import annotations

from pathlib import Path

SAMPLE = """\
Building configuration...

Current configuration : 6150 bytes
!
! Last configuration change at 09:12:44 UTC Wed Oct 14 2026
!
version 17.9
service timestamps debug datetime msec
service timestamps log datetime msec
platform qfp utilization monitor load 80
!
hostname branch-r1
!
boot-start-marker
boot-end-marker
!
vrf definition Mgmt-intf
 address-family ipv4
 exit-address-family
!
no aaa new-model
!
ip domain name example.com
!
ip port-map mailsub port tcp 587
!
object-group network SERVERS
 description the servers in the DMZ
 host 10.20.0.10
 host 10.20.0.25
 range 10.20.0.40 10.20.0.45
object-group network ADMINS
 host 10.10.5.10
 10.10.6.0 255.255.255.0
object-group network ALL-ADMIN
 group-object ADMINS
 host 198.51.100.200
object-group service WEB-SVC
 description web
 tcp eq www
 tcp eq 443
 tcp range 8000 8010
object-group service MAIL-SVC
 tcp eq smtp
 tcp 587
object-group v6-network SERVERS6
 host 2001:db8:20::10
 2001:db8:20::/64
!
class-map type inspect match-any CM-WEB
 match protocol http
 match protocol https
class-map type inspect match-any CM-DNS
 match protocol dns
class-map type inspect match-all CM-ADMIN
 match access-group name ZB-ADMIN
 match protocol ssh
class-map type inspect match-any CM-TO-SERVERS
 match access-group name ZB-SERVERS
 match access-group name ZB-SERVERS6
class-map type inspect match-any CM-MAIL-SUB
 match protocol mailsub
class-map type inspect match-any CM-VPN
 match access-group name ZB-GRE
class-map type inspect match-any CM-PING
 match protocol icmp
!
policy-map type inspect PM-IN-OUT
 class type inspect CM-WEB
  inspect
 class type inspect CM-DNS
  inspect
 class type inspect CM-MAIL-SUB
  inspect
 class type inspect CM-VPN
  pass
 class type inspect CM-PING
  inspect
 class class-default
  drop log
policy-map type inspect PM-OUT-DMZ
 class type inspect CM-TO-SERVERS
  inspect
 class class-default
  drop log
policy-map type inspect PM-IN-DMZ
 class type inspect CM-ADMIN
  inspect
 class type inspect CM-TO-SERVERS
  inspect
 class class-default
  drop
policy-map type inspect PM-DMZ-OUT
 class type inspect CM-DNS
  inspect
 class type inspect CM-WEB
  inspect
 class class-default
  drop log
policy-map type inspect PM-TO-ROUTER
 class type inspect CM-PING
  pass
 class class-default
  drop
!
zone security INSIDE
 description users
zone security OUTSIDE
 description the internet
zone security DMZ
 description servers
zone security LAB
 description the lab
zone security MGMT
 description management
zone-pair security ZP-IN-OUT source INSIDE destination OUTSIDE
 service-policy type inspect PM-IN-OUT
zone-pair security ZP-OUT-DMZ source OUTSIDE destination DMZ
 service-policy type inspect PM-OUT-DMZ
zone-pair security ZP-IN-DMZ source INSIDE destination DMZ
 service-policy type inspect PM-IN-DMZ
zone-pair security ZP-DMZ-OUT source DMZ destination OUTSIDE
 service-policy type inspect PM-DMZ-OUT
zone-pair security ZP-LAB-OUT source LAB destination OUTSIDE
 service-policy type inspect PM-DMZ-OUT
zone-pair security ZP-OUT-SELF source OUTSIDE destination self
 service-policy type inspect PM-TO-ROUTER
!
interface GigabitEthernet0/0/0
 description uplink to the provider
 ip address 203.0.113.2 255.255.255.248
 ip nat outside
 ip access-group WAN-IN in
 zone-member security OUTSIDE
 negotiation auto
 ipv6 address 2001:db8:ffff::2/64
 ipv6 traffic-filter WAN6-IN in
!
interface GigabitEthernet0/0/1
 description users
 ip address 10.10.0.1 255.255.0.0
 ip nat inside
 zone-member security INSIDE
 negotiation auto
 ipv6 address 2001:db8:10::1/64
!
interface GigabitEthernet0/0/2
 description servers
 ip address 10.20.0.1 255.255.255.0
 ip nat inside
 ip access-group DMZ-OUT out
 zone-member security DMZ
 negotiation auto
 ipv6 address 2001:db8:20::1/64
!
interface GigabitEthernet0/0/3
 description lab
 ip address 10.30.0.1 255.255.255.0
 ip access-group 110 in
 zone-member security LAB
 negotiation auto
!
interface GigabitEthernet0
 vrf forwarding Mgmt-intf
 ip address 192.0.2.250 255.255.255.0
 zone-member security MGMT
 negotiation auto
!
interface Loopback0
 ip address 10.255.255.1 255.255.255.255
!
ip forward-protocol nd
ip http server
ip http secure-server
!
ip nat inside source static 10.20.0.10 203.0.113.3
ip nat inside source static tcp 10.20.0.25 25 203.0.113.2 25 extendable
ip nat inside source list NAT-USERS interface GigabitEthernet0/0/0 overload
ip route 0.0.0.0 0.0.0.0 203.0.113.1
!
ip access-list standard NAT-USERS
 10 deny   10.10.99.0 0.0.0.255
 20 permit 10.10.0.0 0.0.255.255
ip access-list extended WAN-IN
 10 remark what may come in at all
 10 deny   ip 10.0.0.0 0.255.255.255 any log
 20 deny   ip 192.168.0.0 0.0.255.255 any log
 30 permit tcp any any established
 40 permit tcp any host 203.0.113.3 eq www
 50 permit tcp any host 203.0.113.3 eq 443
 60 permit tcp any host 203.0.113.2 eq smtp
 70 permit icmp any any echo-reply
 80 permit icmp any any unreachable
 90 permit icmp any any time-exceeded
 100 permit tcp object-group ALL-ADMIN host 203.0.113.3 eq 22
 110 permit gre host 198.51.100.50 any
 120 permit udp any any eq domain
 130 permit tcp any any range 8000 8010 time-range OFFICE
 140 permit ip any any
ip access-list extended DMZ-OUT
 10 remark the servers take only these
 10 permit object-group WEB-SVC any object-group SERVERS
 20 permit tcp any host 10.20.0.25 eq smtp
 30 permit tcp object-group ADMINS object-group SERVERS eq 22
 40 permit icmp any any echo
 50 deny   ip any any log
ip access-list extended ZB-ADMIN
 10 permit ip object-group ADMINS any
ip access-list extended ZB-SERVERS
 10 permit object-group WEB-SVC any object-group SERVERS
 20 permit object-group MAIL-SVC any host 10.20.0.25
 30 permit icmp any object-group SERVERS echo
ipv6 access-list ZB-SERVERS6
 sequence 10 permit tcp any object-group SERVERS6 eq www
 sequence 20 permit tcp any object-group SERVERS6 eq 443
ip access-list extended ZB-GRE
 10 permit gre any host 198.51.100.50
ipv6 access-list WAN6-IN
 sequence 10 permit tcp any host 2001:db8:20::10 eq www
 sequence 20 permit tcp any host 2001:db8:20::10 eq 443
 sequence 30 permit icmp any any echo-reply
 sequence 40 permit icmp any any packet-too-big
 sequence 50 deny ipv6 any any log
ip access-list extended 110
 10 permit tcp 10.30.0.0 0.0.0.255 any eq www
 20 permit tcp 10.30.0.0 0.0.0.255 any eq 443
 30 permit udp 10.30.0.0 0.0.0.255 host 10.20.0.53 eq domain
 40 deny   ip any any fragments
 50 deny   ip any any log
!
time-range OFFICE
 periodic weekdays 8:00 to 18:00
!
line con 0
 stopbits 1
line vty 0 4
 login local
 transport input ssh
!
end
"""


def main() -> None:
    path = Path(__file__).resolve().parent.parent / "data" / "ios_sample.cfg"
    path.write_text(SAMPLE, encoding="utf-8")
    print(f"wrote {path}")


if __name__ == "__main__":
    main()
