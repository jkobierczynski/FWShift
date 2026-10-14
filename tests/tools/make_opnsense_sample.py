# FWShift - multi-vendor firewall policy converter
# Copyright (C) 2026 Jurgen Kobierczynski
# SPDX-License-Identifier: GPL-3.0-or-later

"""Write tests/data/opnsense_sample.xml: a made-up OPNsense 26.7 config.xml.

The configuration below was written by hand to the models of OPNsense 26.7 (Firewall/Filter 1.0.6, Alias 1.0.1,
the port forwards of 26.1) and holds both kinds of filter rule: those of the "Rules [new]" pages and those of
<filter>, which 26.7 still reads. It was not taken from a firewall.

Every address is a documentation or private address (RFC 5737, RFC 1918, RFC 3849). Not taken from any real network.

    python3 tests/tools/make_opnsense_sample.py
"""

from __future__ import annotations

from pathlib import Path

CONFIG = """\
<?xml version="1.0"?>
<opnsense>
  <system>
    <hostname>fw-sample</hostname>
    <domain>example.net</domain>
    <webgui><protocol>https</protocol></webgui>
    <disablenatreflection>yes</disablenatreflection>
    <disablefilter>0</disablefilter>
  </system>
  <interfaces>
    <wan>
      <enable>1</enable><if>vtnet0</if><descr>WAN</descr>
      <ipaddr>203.0.113.2</ipaddr><subnet>24</subnet><gateway>WAN_GW</gateway>
      <ipaddrv6>2001:db8:ffff::2</ipaddrv6><subnetv6>64</subnetv6><gatewayv6>WAN_GW6</gatewayv6>
      <blockpriv>1</blockpriv><blockbogons>1</blockbogons>
    </wan>
    <lan>
      <enable>1</enable><if>vtnet1</if><descr>LAN</descr>
      <ipaddr>192.168.10.1</ipaddr><subnet>24</subnet>
      <ipaddrv6>2001:db8:10::1</ipaddrv6><subnetv6>64</subnetv6>
      <blockpriv>0</blockpriv><blockbogons/>
    </lan>
    <opt1>
      <enable>1</enable><if>vtnet2</if><descr>DMZ</descr>
      <ipaddr>172.16.20.1</ipaddr><subnet>24</subnet>
      <ipaddrv6>2001:db8:20::1</ipaddrv6><subnetv6>64</subnetv6>
    </opt1>
    <opt2>
      <enable>1</enable><if>vtnet3</if><descr>GUEST</descr>
      <ipaddr>192.168.30.1</ipaddr><subnet>24</subnet>
    </opt2>
    <opt3>
      <if>vtnet4</if><descr>SPARE</descr>
      <ipaddr>192.168.40.1</ipaddr><subnet>24</subnet>
    </opt3>
    <opt4>
      <enable>1</enable><if>ovpns1</if><descr>VPNSITE</descr>
      <ipaddr>10.8.1.1</ipaddr><subnet>24</subnet>
    </opt4>
    <INSIDE>
      <internal_dynamic>1</internal_dynamic><enable>1</enable><if>INSIDE</if><descr>INSIDE</descr>
      <virtual>1</virtual><type>group</type><networks/>
    </INSIDE>
    <openvpn>
      <internal_dynamic>1</internal_dynamic><enable>1</enable><if>openvpn</if><descr>OpenVPN</descr>
      <virtual>1</virtual><type>group</type><networks/>
    </openvpn>
  </interfaces>
  <ifgroups version="1.0.0">
    <ifgroupentry uuid="0b7d1c4e-2f3a-4d5b-8c6d-7e8f9a0b1c01">
      <ifname>INSIDE</ifname><members>lan,opt1</members><nogroup>0</nogroup>
      <sequence>10</sequence><descr>Inside networks</descr>
    </ifgroupentry>
  </ifgroups>
  <filter>
    <rule uuid="1a000000-0000-4000-8000-000000000001">
      <type>block</type><quick>0</quick><interface>lan</interface><direction>in</direction>
      <ipprotocol>inet</ipprotocol>
      <source><any>1</any></source>
      <destination><address>198.51.100.0/24</address></destination>
      <descr>LAN to test net (not quick)</descr>
    </rule>
    <rule uuid="1a000000-0000-4000-8000-000000000002">
      <type>pass</type><quick>1</quick><interface>INSIDE</interface><direction>in</direction>
      <ipprotocol>inet</ipprotocol><protocol>icmp</protocol><icmptype>echoreq</icmptype>
      <source><network>INSIDE</network></source>
      <destination><any>1</any></destination>
      <descr>Inside may ping (old kind)</descr>
    </rule>
    <rule uuid="1a000000-0000-4000-8000-000000000003">
      <type>pass</type><interface>opt2</interface>
      <source><network>opt2</network></source>
      <destination><address>192.0.2.80</address><port>80</port></destination>
      <descr>Guests to the portal (no protocol, both IP versions)</descr>
    </rule>
    <rule uuid="1a000000-0000-4000-8000-000000000004">
      <type>block</type><floating>yes</floating><quick>1</quick><interface>wan</interface>
      <direction>out</direction><ipprotocol>inet</ipprotocol>
      <source><network>opt2</network></source>
      <destination><address>Blocklist</address></destination>
      <log>1</log><category>Security</category>
      <descr>Guests never to the blocklist</descr>
    </rule>
    <rule uuid="1a000000-0000-4000-8000-000000000005">
      <type>pass</type><quick>1</quick><interface>opt1</interface><direction>in</direction>
      <ipprotocol>inet</ipprotocol><disabled>1</disabled>
      <source><network>opt1</network></source>
      <destination><network>lan</network><not>1</not></destination>
      <descr>DMZ anywhere but LAN (disabled)</descr>
    </rule>
    <rule uuid="1a000000-0000-4000-8000-000000000006">
      <type>pass</type><quick>1</quick><interface>opt2</interface><direction>in</direction>
      <ipprotocol>inet</ipprotocol><protocol>tcp</protocol><tos>0x10</tos>
      <source><network>opt2</network></source>
      <destination><any>1</any></destination>
      <descr>Guests interactive (tos)</descr>
    </rule>
    <rule uuid="1a000000-0000-4000-8000-000000000007">
      <type>pass</type><quick>1</quick><interface>opt2</interface><direction>in</direction>
      <ipprotocol>inet6</ipprotocol><protocol>icmp</protocol>
      <source><any>1</any></source>
      <destination><any>1</any></destination>
      <descr>ICMP for IPv6 only (matches nothing)</descr>
    </rule>
    <rule uuid="1a000000-0000-4000-8000-000000000008">
      <type>pass</type><quick>1</quick><interface>openvpn</interface><direction>in</direction>
      <ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><any>1</any></source>
      <destination><network>lan</network><port>443</port></destination>
      <descr>VPN users to LAN web (old kind)</descr>
    </rule>
  </filter>
  <nat>
    <outbound>
      <mode>hybrid</mode>
      <rule>
        <interface>wan</interface><ipprotocol>inet</ipprotocol>
        <source><network>192.168.30.0/24</network></source>
        <destination><any>1</any></destination>
        <target>203.0.113.30</target>
        <disabled>0</disabled><nonat>0</nonat><staticnatport>0</staticnatport>
        <descr>Guests leave as .30</descr>
      </rule>
    </outbound>
    <rule uuid="4d000000-0000-4000-8000-000000000001">
      <sequence>100</sequence><disabled>0</disabled><nordr>0</nordr>
      <interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp</protocol>
      <source><network>any</network><port/><not>0</not></source>
      <destination><network>wanip</network><port>2222</port><not>0</not></destination>
      <target>172.16.20.10</target><local-port>22</local-port>
      <log>0</log><category>Remote</category><descr>SSH to bastion</descr>
      <natreflection>disable</natreflection><pass>rule</pass>
    </rule>
    <rule uuid="4d000000-0000-4000-8000-000000000002">
      <sequence>200</sequence><disabled>0</disabled><nordr>0</nordr>
      <interface>wan</interface><ipprotocol>inet</ipprotocol><protocol>tcp/udp</protocol>
      <source><network>198.51.100.0/24</network><port/><not>0</not></source>
      <destination><network>wanip</network><port>5060</port><not>0</not></destination>
      <target>172.16.20.20</target><local-port>5060</local-port>
      <log>0</log><category/><descr>Voice from the partner</descr>
      <natreflection/><pass>pass</pass>
    </rule>
  </nat>
  <OPNsense>
    <Interfaces><settings version="1.0.0"><disableipv6>0</disableipv6></settings></Interfaces>
    <Firewall>
      <Alias version="1.0.1">
        <geoip><url/></geoip>
        <aliases>
          <alias uuid="2b000000-0000-4000-8000-000000000001">
            <enabled>1</enabled><name>WebServers</name><type>host</type>
            <content>172.16.20.10
2001:db8:20::10</content><description>Web servers</description>
          </alias>
          <alias uuid="2b000000-0000-4000-8000-000000000002">
            <enabled>1</enabled><name>WebPorts</name><type>port</type>
            <content>80
443
8000:8080</content><description>Web ports</description>
          </alias>
          <alias uuid="2b000000-0000-4000-8000-000000000003">
            <enabled>1</enabled><name>Blocklist</name><type>network</type>
            <content>198.51.100.0/24
203.0.113.128/25
!198.51.100.7</content><description>Blocked networks, one exception</description>
          </alias>
          <alias uuid="2b000000-0000-4000-8000-000000000004">
            <enabled>1</enabled><name>Inside_nets</name><type>networkgroup</type>
            <content>__lan_network
__opt1_network</content><description>LAN and DMZ</description>
          </alias>
          <alias uuid="2b000000-0000-4000-8000-000000000005">
            <enabled>1</enabled><name>Geo_block</name><type>geoip</type><proto>IPv4,IPv6</proto>
            <content>ZZ</content><description>Countries by name only</description>
          </alias>
          <alias uuid="2b000000-0000-4000-8000-000000000006">
            <enabled>1</enabled><name>Updates</name><type>host</type>
            <content>updates.example.net
192.0.2.10-192.0.2.13</content><description>Update servers</description>
          </alias>
          <alias uuid="2b000000-0000-4000-8000-000000000007">
            <enabled>0</enabled><name>Old_partner</name><type>network</type>
            <content>198.51.100.192/26</content><description>No longer used</description>
          </alias>
          <alias uuid="2b000000-0000-4000-8000-000000000008">
            <enabled>1</enabled><name>Servers_all</name><type>host</type>
            <content>WebServers
Old_partner
172.16.20.20</content><description>Every server</description>
          </alias>
        </aliases>
      </Alias>
      <Category version="1.0.0">
        <categories>
          <category uuid="3c000000-0000-4000-8000-000000000001"><name>Web</name><auto>0</auto><color>3366cc</color></category>
          <category uuid="3c000000-0000-4000-8000-000000000002"><name>Security</name><auto>0</auto><color/></category>
        </categories>
      </Category>
      <Filter version="1.0.6">
        <rules>
          <rule uuid="5e000000-0000-4000-8000-000000000001">
            <enabled>1</enabled><statetype>keep</statetype><sequence>1</sequence><action>pass</action>
            <quick>1</quick><interfacenot>0</interfacenot><interface>lan</interface><direction>in</direction>
            <ipprotocol>inet46</ipprotocol><protocol>any</protocol>
            <source_net>lan</source_net><source_not>0</source_not><source_port/>
            <destination_net>any</destination_net><destination_not>0</destination_not><destination_port/>
            <log>0</log><categories/><description>Default allow LAN to any rule</description>
          </rule>
          <rule uuid="5e000000-0000-4000-8000-000000000002">
            <enabled>1</enabled><statetype>keep</statetype><sequence>100</sequence><action>pass</action>
            <quick>1</quick><interfacenot>0</interfacenot><interface>wan</interface><direction>in</direction>
            <ipprotocol>inet46</ipprotocol><protocol>TCP</protocol>
            <source_net>any</source_net><source_not>0</source_not><source_port/>
            <destination_net>WebServers</destination_net><destination_not>0</destination_not>
            <destination_port>WebPorts</destination_port>
            <log>1</log><categories>3c000000-0000-4000-8000-000000000001</categories>
            <description>Web publishing</description>
          </rule>
          <rule uuid="5e000000-0000-4000-8000-000000000003">
            <enabled>1</enabled><statetype>keep</statetype><sequence>200</sequence><action>block</action>
            <quick>1</quick><interfacenot>0</interfacenot><interface>wan,opt1</interface>
            <direction>out</direction><ipprotocol>inet</ipprotocol><protocol>any</protocol>
            <source_net>any</source_net><source_not>0</source_not>
            <destination_net>Blocklist,Geo_block</destination_net><destination_not>0</destination_not>
            <log>1</log><categories>3c000000-0000-4000-8000-000000000002</categories>
            <description>Never to the blocklist (floating)</description>
          </rule>
          <rule uuid="5e000000-0000-4000-8000-000000000004">
            <enabled>1</enabled><statetype>keep</statetype><sequence>300</sequence><action>reject</action>
            <quick>1</quick><interfacenot>0</interfacenot><interface>INSIDE</interface><direction>in</direction>
            <ipprotocol>inet</ipprotocol><protocol>TCP/UDP</protocol>
            <source_net>any</source_net><source_not>0</source_not>
            <destination_net>192.0.2.53</destination_net><destination_not>0</destination_not>
            <destination_port>53</destination_port>
            <log>0</log><description>No outside resolver (group)</description>
          </rule>
          <rule uuid="5e000000-0000-4000-8000-000000000005">
            <enabled>1</enabled><statetype>keep</statetype><sequence>400</sequence><action>block</action>
            <quick>1</quick><interfacenot>0</interfacenot><interface>wan</interface><direction>out</direction>
            <received-on>opt1</received-on><received-on-not>0</received-on-not>
            <ipprotocol>inet</ipprotocol><protocol>TCP</protocol>
            <source_net>any</source_net><source_not>0</source_not>
            <destination_net>any</destination_net><destination_not>0</destination_not>
            <destination_port>25</destination_port>
            <log>0</log><description>DMZ may not send mail out (received-on)</description>
          </rule>
          <rule uuid="5e000000-0000-4000-8000-000000000006">
            <enabled>0</enabled><statetype>keep</statetype><sequence>500</sequence><action>pass</action>
            <quick>1</quick><interfacenot>0</interfacenot><interface>opt1</interface><direction>in</direction>
            <ipprotocol>inet</ipprotocol><protocol>any</protocol>
            <source_net>opt1</source_net><source_not>0</source_not>
            <destination_net>lan</destination_net><destination_not>1</destination_not>
            <log>0</log><description>DMZ anywhere but LAN (disabled)</description>
          </rule>
          <rule uuid="5e000000-0000-4000-8000-000000000007">
            <enabled>1</enabled><statetype>keep</statetype><sequence>600</sequence><action>pass</action>
            <quick>1</quick><interfacenot>0</interfacenot><interface>opt1</interface><direction>in</direction>
            <ipprotocol>inet6</ipprotocol><protocol>IPV6-ICMP</protocol><icmp6type>128,135,136</icmp6type>
            <source_net>opt1</source_net><source_not>0</source_not>
            <destination_net>any</destination_net><destination_not>0</destination_not>
            <log>0</log><description>DMZ ICMPv6</description>
          </rule>
          <rule uuid="5e000000-0000-4000-8000-000000000008">
            <enabled>1</enabled><statetype>keep</statetype><sequence>700</sequence><action>pass</action>
            <quick>1</quick><interfacenot>0</interfacenot><interface>opt1</interface><direction>in</direction>
            <ipprotocol>inet</ipprotocol><protocol>TCP</protocol>
            <source_net>WebServers,172.16.20.20</source_net><source_not>0</source_not>
            <destination_net>Updates,Servers_all</destination_net><destination_not>0</destination_not>
            <destination_port>443</destination_port><gateway>WAN_GW</gateway>
            <log>0</log><description>Servers fetch updates</description>
          </rule>
          <rule uuid="5e000000-0000-4000-8000-000000000009">
            <enabled>1</enabled><statetype>keep</statetype><sequence>800</sequence><action>block</action>
            <quick>1</quick><interfacenot>0</interfacenot><interface>opt2</interface><direction>in</direction>
            <ipprotocol>inet</ipprotocol><protocol>any</protocol>
            <source_net>any</source_net><source_not>0</source_not>
            <destination_net>Inside_nets</destination_net><destination_not>0</destination_not>
            <log>1</log><description>Guests stay out</description>
          </rule>
          <rule uuid="5e000000-0000-4000-8000-00000000000a">
            <enabled>1</enabled><statetype>keep</statetype><sequence>900</sequence><action>pass</action>
            <quick>1</quick><interfacenot>0</interfacenot><interface>openvpn</interface><direction>in</direction>
            <ipprotocol>inet</ipprotocol><protocol>TCP</protocol>
            <source_net>any</source_net><source_not>0</source_not>
            <destination_net>WebServers</destination_net><destination_not>0</destination_not>
            <destination_port>22</destination_port>
            <log>0</log><description>VPN users to the web servers</description>
          </rule>
          <rule uuid="5e000000-0000-4000-8000-00000000000b">
            <enabled>1</enabled><statetype>keep</statetype><sequence>1000</sequence><action>pass</action>
            <quick>0</quick><interfacenot>0</interfacenot><interface>wan,lan,opt1,opt2</interface>
            <direction>in</direction><ipprotocol>inet</ipprotocol><protocol>UDP</protocol>
            <source_net>any</source_net><source_not>0</source_not>
            <destination_net>192.0.2.123</destination_net><destination_not>0</destination_not>
            <destination_port>123</destination_port>
            <log>0</log><description>Time for everyone (floating, not quick)</description>
          </rule>
        </rules>
        <snatrules>
          <rule uuid="6f000000-0000-4000-8000-000000000001">
            <enabled>1</enabled><nonat>0</nonat><sequence>100</sequence><interface>wan</interface>
            <ipprotocol>inet</ipprotocol><protocol>any</protocol>
            <source_net>172.16.20.0/24</source_net><source_not>0</source_not><source_port/>
            <destination_net>any</destination_net><destination_not>0</destination_not><destination_port/>
            <target>203.0.113.10</target><target_port/><staticnatport>0</staticnatport>
            <log>0</log><categories/><description>DMZ leaves as .10</description>
          </rule>
        </snatrules>
        <npt>
          <rule uuid="70000000-0000-4000-8000-000000000001">
            <enabled>1</enabled><log>0</log><sequence>100</sequence><interface>wan</interface>
            <source_net>2001:db8:10::/64</source_net><destination_net>2001:db8:ffff:10::/64</destination_net>
            <trackif/><categories/><description>LAN prefix translation</description>
          </rule>
        </npt>
        <onetoone>
          <rule uuid="71000000-0000-4000-8000-000000000001">
            <enabled>1</enabled><log>0</log><sequence>100</sequence><interface>wan</interface>
            <type>binat</type><source_net>172.16.20.50/32</source_net><source_not>0</source_not>
            <destination_net>any</destination_net><destination_not>0</destination_not>
            <external>203.0.113.50/32</external><natreflection/><categories/>
            <description>Mail relay 1:1</description>
          </rule>
        </onetoone>
      </Filter>
    </Firewall>
  </OPNsense>
</opnsense>
"""


def main() -> None:
    out = Path(__file__).resolve().parents[1] / "data" / "opnsense_sample.xml"
    out.write_text(CONFIG, encoding="utf-8")
    print(f"wrote {out}")


if __name__ == "__main__":
    main()
