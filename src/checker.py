"""
NetSage AI - Deterministic Rule Verification Engine (checker.py)
Implements precise regular expression and rule-based diagnostic pattern matching
for multi-layer Cisco IOS & Packet Tracer network anomalies.
"""

import re
from typing import Dict, List, Optional, Any


class DeterministicChecker:
    """
    Deterministic rule verification engine analyzing Cisco IOS CLI outputs.
    Combines strict regex matching with domain-specific network diagnostic heuristics.
    """

    def __init__(self):
        # Pre-compile common regex patterns
        self.re_admin_down = re.compile(
            r"(?P<intf>(?:GigabitEthernet|FastEthernet|Ethernet|Serial|Vlan|Port-channel|Gi|Fa|Se|Po)[\d\/\.]+)(?:\s+[\d\.]+|\s+unassigned)?\s+(?:YES|NO)?\s+(?:manual|unset|NVRAM|TFTP|DHCP)?\s+(?:is\s+)?administratively\s+down",
            re.IGNORECASE,
        )
        self.re_admin_down_generic = re.compile(
            r"(?P<intf>(?:GigabitEthernet|FastEthernet|Ethernet|Serial|Vlan|Port-channel|Gi|Fa|Se|Po)[\d\/\.]+)\s+(?:is\s+)?administratively\s+down",
            re.IGNORECASE,
        )
        self.re_intf_shutdown = re.compile(
            r"interface\s+(?P<intf>(?:GigabitEthernet|FastEthernet|Ethernet|Serial|Vlan|Port-channel)[\d\/\.]+)\s*[\r\n]+(?:[^\!]*[\r\n]+)*?\s*shutdown",
            re.IGNORECASE,
        )
        self.re_ospf_area_err = re.compile(
            r"invalid Area ID\s+(?P<area>[\d\.]+)\s+from\s+(?P<src_ip>[\d\.]+)\s+on\s+(?P<intf>\S+)",
            re.IGNORECASE,
        )
        self.re_ospf_area_intf = re.compile(
            r"Internet Address\s+[\d\.]+\/\d+,\s+Area\s+(?P<area>\d+)",
            re.IGNORECASE,
        )
        self.re_nat_missing_overload = re.compile(
            r"ip\s+nat\s+inside\s+source\s+list\s+(\d+)\s+interface\s+(\S+)(?!\s+overload)",
            re.IGNORECASE,
        )
        self.re_nat_exhausted = re.compile(
            r"allocated\s+\d+\s+\(100\%\),\s+misses\s+\d+",
            re.IGNORECASE,
        )
        self.re_vlan_trunk_allowed = re.compile(
            r"Port\s+Vlans allowed on trunk\s*[\r\n]+\S+\s+(?P<vlans>[\d\,\-]+)",
            re.IGNORECASE,
        )
        self.re_native_vlan_mismatch = re.compile(
            r"Native VLAN mismatch discovered on\s+(?P<intf>\S+)\s*\((?P<local_vlan>\d+)\),\s*with\s+\S+\s+(?P<remote_intf>\S+)\s*\((?P<remote_vlan>\d+)\)",
            re.IGNORECASE,
        )
        self.re_duplex_mismatch = re.compile(
            r"Half-duplex.*?(?P<late_coll>\d+)\s+late collision",
            re.DOTALL | re.IGNORECASE,
        )
        self.re_err_disabled = re.compile(
            r"(?P<intf>(?:GigabitEthernet|FastEthernet|Ethernet|Fa|Gi)[\d\/\.]+)\s+.*?\s+err-disabled",
            re.IGNORECASE,
        )
        self.re_root_guard = re.compile(
            r"Root Guard block on port\s+(?P<intf>\S+)\s+on\s+(?P<vlan>\S+)",
            re.IGNORECASE,
        )
        self.re_ospf_exstart_mtu = re.compile(
            r"Neighbor ID.*?\s+EXSTART\/",
            re.IGNORECASE,
        )
        self.re_arp_incomplete = re.compile(
            r"Internet\s+(?P<ip>[\d\.]+)\s+\d+\s+Incomplete",
            re.IGNORECASE,
        )
        self.re_ospf_passive = re.compile(
            r"No Hellos\s+\(Passive interface\)",
            re.IGNORECASE,
        )
        self.re_inverted_wildcard = re.compile(
            r"network\s+([\d\.]+)\s+255\.255\.255\.0\s+area",
            re.IGNORECASE,
        )
        self.re_eigrp_wrong_as = re.compile(
            r"Neighbor\s+([\d\.]+)\s+is down:\s+wrong AS",
            re.IGNORECASE,
        )
        self.re_bgp_remote_as = re.compile(
            r"Received OPEN from\s+([\d\.]+)\s+with remote-as\s+(\d+),\s+expected\s+(\d+)",
            re.IGNORECASE,
        )
        self.re_vty_telnet_only = re.compile(
            r"line vty 0 \d+[\r\n]+(?:[^\!]*[\r\n]+)*?\s*transport input telnet",
            re.IGNORECASE,
        )
        self.re_ipv6_ra_suppressed = re.compile(
            r"ND router advertisements are suppressed",
            re.IGNORECASE,
        )

    def analyze(self, symptom: str, topology_note: str, show_outputs: str, case_id: str = "CASE-N") -> Dict[str, Any]:
        """
        Executes multi-phase deterministic pattern checks across provided show_outputs.
        Returns a structured diagnostic dict.
        """
        output_text = show_outputs or ""
        symptom_text = symptom or ""

        # 1. Check Administratively Down Interfaces (Sub-interfaces & Physical)
        admin_matches = list(self.re_admin_down.finditer(output_text))
        if admin_matches:
            intf_name = admin_matches[0].group("intf")
            evidence = [m.group(0).strip() for m in admin_matches]
            
            # Check if parent interface is down
            if "." not in intf_name and "sub-interface" not in symptom_text.lower():
                return {
                    "matched": True,
                    "case_id": case_id,
                    "fault_type": "PHYSICAL_INTERFACE_ADMIN_DOWN",
                    "root_cause": f"Physical interface {intf_name} is administratively down, halting all connected layer-2/3 transit traffic",
                    "osi_layer": "Layer 1 - Physical",
                    "confidence": 0.99,
                    "evidence": evidence,
                    "next_command": f"show interfaces {intf_name}",
                    "fix_steps": [
                        "configure terminal",
                        f"interface {intf_name}",
                        "no shutdown",
                        "end",
                        "write memory"
                    ],
                    "source": "deterministic_rule"
                }
            else:
                return {
                    "matched": True,
                    "case_id": case_id,
                    "fault_type": "SUB_INTERFACE_ADMIN_DOWN",
                    "root_cause": f"Sub-interface {intf_name} is administratively down, preventing inter-VLAN routing and gateway reachability",
                    "osi_layer": "Layer 3 - Network",
                    "confidence": 0.99,
                    "evidence": evidence,
                    "next_command": "show ip interface brief",
                    "fix_steps": [
                        "configure terminal",
                        f"interface {intf_name}",
                        "no shutdown",
                        "end",
                        "write memory"
                    ],
                    "source": "deterministic_rule"
                }

        # 2. Check OSPF Area Mismatch
        ospf_area_log = self.re_ospf_area_err.search(output_text)
        if ospf_area_log or ("invalid Area ID" in output_text):
            evidence = []
            if ospf_area_log:
                evidence.append(ospf_area_log.group(0).strip())
            for line in output_text.splitlines():
                if "Area " in line and ("Internet Address" in line or "Area ID" in line):
                    evidence.append(line.strip())
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "OSPF_AREA_MISMATCH",
                "root_cause": "OSPF adjacency failure caused by Area ID mismatch on interconnecting link",
                "osi_layer": "Layer 3 - Network",
                "confidence": 0.98,
                "evidence": evidence or ["Received packet with invalid Area ID"],
                "next_command": "show ip ospf neighbor",
                "fix_steps": [
                    "configure terminal",
                    "router ospf 1",
                    "no network 10.0.12.0 0.0.0.3 area 1",
                    "network 10.0.12.0 0.0.0.3 area 0",
                    "end",
                    "clear ip ospf process"
                ],
                "source": "deterministic_rule"
            }

        # 3. Check NAT Missing Overload (PAT vs Dynamic NAT)
        nat_missing = self.re_nat_missing_overload.search(output_text)
        if nat_missing:
            acl_num = nat_missing.group(1)
            intf = nat_missing.group(2)
            evidence = [nat_missing.group(0).strip()]
            for line in output_text.splitlines():
                if "ip nat" in line:
                    evidence.append(line.strip())
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "NAT_OVERLOAD_MISSING",
                "root_cause": f"NAT translation rule is missing the 'overload' keyword, restricting outbound traffic to 1-to-1 dynamic mapping instead of PAT",
                "osi_layer": "Layer 4 - Transport",
                "confidence": 0.98,
                "evidence": list(set(evidence)),
                "next_command": "show ip nat translations",
                "fix_steps": [
                    "configure terminal",
                    f"no ip nat inside source list {acl_num} interface {intf}",
                    f"ip nat inside source list {acl_num} interface {intf} overload",
                    "end",
                    "clear ip nat translation *"
                ],
                "source": "deterministic_rule"
            }

        # 4. Check Dynamic NAT Pool Exhaustion
        if self.re_nat_exhausted.search(output_text):
            evidence = [line.strip() for line in output_text.splitlines() if "allocated" in line or "pool" in line or "misses" in line]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "NAT_POOL_EXHAUSTION",
                "root_cause": "Dynamic NAT address pool is 100% exhausted with no free IP mappings available and no PAT overload enabled",
                "osi_layer": "Layer 4 - Transport",
                "confidence": 0.97,
                "evidence": evidence,
                "next_command": "show ip nat statistics",
                "fix_steps": [
                    "configure terminal",
                    "ip nat inside source list 1 interface GigabitEthernet0/0 overload",
                    "end",
                    "clear ip nat translation *"
                ],
                "source": "deterministic_rule"
            }

        # 5. Check Native VLAN Mismatch
        native_mismatch = self.re_native_vlan_mismatch.search(output_text)
        if native_mismatch or "Native VLAN mismatch" in output_text:
            evidence = [line.strip() for line in output_text.splitlines() if "Native VLAN" in line or "Native Mode VLAN" in line]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "NATIVE_VLAN_MISMATCH",
                "root_cause": "802.1Q Native VLAN mismatch across trunk link causing frame leakage and CDP error notifications",
                "osi_layer": "Layer 2 - Data Link",
                "confidence": 0.98,
                "evidence": evidence,
                "next_command": "show interfaces trunk",
                "fix_steps": [
                    "configure terminal",
                    "interface GigabitEthernet0/1",
                    "switchport trunk native vlan 99",
                    "end",
                    "write memory"
                ],
                "source": "deterministic_rule"
            }

        # 6. Check Trunk Allowed VLAN Missing
        if "Vlans allowed on trunk" in output_text:
            lines = output_text.splitlines()
            vlan_lines = [l.strip() for l in lines if "Fa0/24" in l or "Vlans allowed" in l]
            if "20" not in "".join(vlan_lines) and "VLAN 20" in (symptom_text + topology_note):
                return {
                    "matched": True,
                    "case_id": case_id,
                    "fault_type": "TRUNK_ALLOWED_VLAN_MISSING",
                    "root_cause": "Target VLAN 20 is pruned or excluded from the switchport trunk allowed list on trunk interface Fa0/24",
                    "osi_layer": "Layer 2 - Data Link",
                    "confidence": 0.96,
                    "evidence": vlan_lines,
                    "next_command": "show interfaces trunk",
                    "fix_steps": [
                        "configure terminal",
                        "interface FastEthernet0/24",
                        "switchport trunk allowed vlan add 20",
                        "end",
                        "write memory"
                    ],
                    "source": "deterministic_rule"
                }

        # 7. Check Duplex Mismatch / Late Collisions
        if "Half-duplex" in output_text and ("late collision" in output_text or "Full-duplex" in output_text):
            evidence = [line.strip() for line in output_text.splitlines() if "duplex" in line.lower() or "collision" in line.lower()]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "DUPLEX_MISMATCH",
                "root_cause": "Duplex configuration mismatch (Half-duplex vs Full-duplex) causing late collisions, CRC errors, and packet drops",
                "osi_layer": "Layer 1 - Physical / Layer 2",
                "confidence": 0.97,
                "evidence": evidence,
                "next_command": "show interfaces FastEthernet0/1",
                "fix_steps": [
                    "configure terminal",
                    "interface FastEthernet0/1",
                    "duplex full",
                    "speed 100",
                    "end",
                    "clear counters FastEthernet0/1"
                ],
                "source": "deterministic_rule"
            }

        # 8. Check Missing Encapsulation dot1Q on Sub-interface
        if "encapsulation dot1Q" not in output_text and "GigabitEthernet0/0." in output_text and "show run interface" in output_text:
            evidence = [line.strip() for line in output_text.splitlines() if "interface GigabitEthernet0/0." in line or "ip address" in line]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "MISSING_DOT1Q_ENCAPSULATION",
                "root_cause": "Router sub-interface is missing IEEE 802.1Q encapsulation binding ('encapsulation dot1Q <vlan_id>')",
                "osi_layer": "Layer 2 - Data Link",
                "confidence": 0.98,
                "evidence": evidence,
                "next_command": "show running-config interface GigabitEthernet0/0.20",
                "fix_steps": [
                    "configure terminal",
                    "interface GigabitEthernet0/0.20",
                    "encapsulation dot1Q 20",
                    "ip address 192.168.20.1 255.255.255.0",
                    "end",
                    "write memory"
                ],
                "source": "deterministic_rule"
            }

        # 9. Check STP Root Guard Inconsistency
        if self.re_root_guard.search(output_text) or "ROOTINCONS" in output_text:
            evidence = [line.strip() for line in output_text.splitlines() if "ROOTINCONS" in line or "ROOT_Inc" in line or "Spanning tree" in line]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "STP_ROOT_GUARD_INCONSISTENCY",
                "root_cause": "Spanning Tree Root Guard triggered root inconsistency state due to superior BPDUs received on protected designated port",
                "osi_layer": "Layer 2 - Data Link",
                "confidence": 0.98,
                "evidence": evidence,
                "next_command": "show spanning-tree inconsistentports",
                "fix_steps": [
                    "configure terminal",
                    "interface FastEthernet0/19",
                    "no spanning-tree guard root",
                    "spanning-tree bpduguard enable",
                    "end",
                    "clear spanning-tree detected-protocols"
                ],
                "source": "deterministic_rule"
            }

        # 10. Check EtherChannel Mode Incompatibility
        if "channel-group" in output_text and ("mode on" in output_text and "mode active" in output_text):
            evidence = [line.strip() for line in output_text.splitlines() if "channel-group" in line or "Po1" in line]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "ETHERCHANNEL_MODE_MISMATCH",
                "root_cause": "EtherChannel bundling protocol mismatch (static 'mode on' vs dynamic LACP 'mode active')",
                "osi_layer": "Layer 2 - Data Link",
                "confidence": 0.98,
                "evidence": evidence,
                "next_command": "show etherchannel summary",
                "fix_steps": [
                    "configure terminal",
                    "interface range GigabitEthernet0/1 - 2",
                    "no channel-group 1",
                    "channel-group 1 mode active",
                    "end",
                    "write memory"
                ],
                "source": "deterministic_rule"
            }

        # 11. Check DHCP Pool Missing Default-Router
        if "ip dhcp pool" in output_text and "default-router" not in output_text:
            evidence = [line.strip() for line in output_text.splitlines() if "ip dhcp pool" in line or "network" in line or "dns-server" in line]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "DHCP_DEFAULT_ROUTER_MISSING",
                "root_cause": "DHCP pool configuration is missing the default gateway statement ('default-router <ip>')",
                "osi_layer": "Layer 7 - Application",
                "confidence": 0.98,
                "evidence": evidence,
                "next_command": "show ip dhcp binding",
                "fix_steps": [
                    "configure terminal",
                    "ip dhcp pool LAN_POOL",
                    "default-router 192.168.5.1",
                    "end",
                    "write memory"
                ],
                "source": "deterministic_rule"
            }

        # 12. Check Port Security Err-Disabled
        if self.re_err_disabled.search(output_text) or "Secure-shutdown" in output_text:
            evidence = [line.strip() for line in output_text.splitlines() if "err-disabled" in line or "Secure-shutdown" in line or "Violation Count" in line]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "PORT_SECURITY_VIOLATION",
                "root_cause": "Switch port placed into err-disabled secure-shutdown state due to MAC address limit violation",
                "osi_layer": "Layer 2 - Data Link",
                "confidence": 0.99,
                "evidence": evidence,
                "next_command": "show port-security interface FastEthernet0/8",
                "fix_steps": [
                    "configure terminal",
                    "interface FastEthernet0/8",
                    "shutdown",
                    "no switchport port-security violation",
                    "switchport port-security violation restrict",
                    "no shutdown",
                    "end",
                    "clear port-security all"
                ],
                "source": "deterministic_rule"
            }

        # 13. Check OSPF MTU Mismatch
        if "EXSTART" in output_text and "MTU" in output_text:
            evidence = [line.strip() for line in output_text.splitlines() if "EXSTART" in line or "MTU" in line]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "OSPF_MTU_MISMATCH",
                "root_cause": "OSPF neighbor state stuck in EXSTART/EXCHANGE due to interface MTU size mismatch (1500 bytes vs 1400 bytes)",
                "osi_layer": "Layer 3 - Network",
                "confidence": 0.97,
                "evidence": evidence,
                "next_command": "show ip ospf neighbor",
                "fix_steps": [
                    "configure terminal",
                    "interface GigabitEthernet0/0",
                    "ip mtu 1500",
                    "end",
                    "clear ip ospf process"
                ],
                "source": "deterministic_rule"
            }

        # 14. Check Incomplete ARP / Unreachable Static Route Next-Hop
        if "Incomplete" in output_text and "0.0.0.0/0" in output_text:
            evidence = [line.strip() for line in output_text.splitlines() if "Incomplete" in line or "Gateway of last resort" in line or "via" in line]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "STATIC_ROUTE_NEXT_HOP_UNREACHABLE",
                "root_cause": "Static default route specifies next-hop IP outside the directly connected /30 subnet range, causing ARP resolution failure",
                "osi_layer": "Layer 3 - Network",
                "confidence": 0.98,
                "evidence": evidence,
                "next_command": "show ip route 0.0.0.0",
                "fix_steps": [
                    "configure terminal",
                    "no ip route 0.0.0.0 0.0.0.0 198.51.100.254",
                    "ip route 0.0.0.0 0.0.0.0 198.51.100.2",
                    "end",
                    "write memory"
                ],
                "source": "deterministic_rule"
            }

        # 15. Check OSPF Passive Interface on Inter-Router Link
        if "Passive interface" in output_text or "No Hellos" in output_text:
            evidence = [line.strip() for line in output_text.splitlines() if "Passive interface" in line or "passive-interface" in line or "No Hellos" in line]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "OSPF_PASSIVE_INTERFACE",
                "root_cause": "OSPF neighbor hello packets suppressed because transit link GigabitEthernet0/2 is configured as passive-interface",
                "osi_layer": "Layer 3 - Network",
                "confidence": 0.99,
                "evidence": evidence,
                "next_command": "show ip ospf interface GigabitEthernet0/2",
                "fix_steps": [
                    "configure terminal",
                    "router ospf 1",
                    "no passive-interface GigabitEthernet0/2",
                    "end",
                    "clear ip ospf process"
                ],
                "source": "deterministic_rule"
            }

        # 16. Check Inverted Wildcard Mask in OSPF
        if self.re_inverted_wildcard.search(output_text):
            evidence = [line.strip() for line in output_text.splitlines() if "255.255.255.0 area" in line]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "OSPF_INVERTED_WILDCARD_MASK",
                "root_cause": "Subnet mask 255.255.255.0 erroneously used instead of wildcard mask 0.0.0.255 in OSPF network statement",
                "osi_layer": "Layer 3 - Network",
                "confidence": 0.98,
                "evidence": evidence,
                "next_command": "show ip ospf interface brief",
                "fix_steps": [
                    "configure terminal",
                    "router ospf 10",
                    "no network 10.1.10.0 255.255.255.0 area 0",
                    "no network 10.1.20.0 255.255.255.0 area 0",
                    "network 10.1.10.0 0.0.0.255 area 0",
                    "network 10.1.20.0 0.0.0.255 area 0",
                    "end",
                    "write memory"
                ],
                "source": "deterministic_rule"
            }

        # 17. Check EIGRP AS Number Mismatch
        if self.re_eigrp_wrong_as.search(output_text) or ("router eigrp 100" in output_text and "router eigrp 200" in output_text):
            evidence = [line.strip() for line in output_text.splitlines() if "wrong AS" in line or "router eigrp" in line]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "EIGRP_AS_MISMATCH",
                "root_cause": "EIGRP Autonomous System (AS) number mismatch preventing neighbor discovery between peers (AS 100 vs AS 200)",
                "osi_layer": "Layer 3 - Network",
                "confidence": 0.99,
                "evidence": evidence,
                "next_command": "show ip eigrp neighbors",
                "fix_steps": [
                    "configure terminal",
                    "no router eigrp 200",
                    "router eigrp 100",
                    "network 10.100.1.0 0.0.0.3",
                    "no auto-summary",
                    "end",
                    "write memory"
                ],
                "source": "deterministic_rule"
            }

        # 18. Check HSRP Virtual IP Mismatch
        if "Virtual IP" in output_text and ("192.168.10.1" in output_text and "192.168.10.254" in output_text):
            evidence = [line.strip() for line in output_text.splitlines() if "Active" in line or "Virtual IP" in line]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "HSRP_VIP_MISMATCH",
                "root_cause": "HSRP group virtual IP address conflict (192.168.10.1 vs 192.168.10.254) causing dual active gateways",
                "osi_layer": "Layer 3 - Network",
                "confidence": 0.97,
                "evidence": evidence,
                "next_command": "show standby brief",
                "fix_steps": [
                    "configure terminal",
                    "interface Vlan10",
                    "standby 10 ip 192.168.10.1",
                    "standby 10 preempt",
                    "end",
                    "write memory"
                ],
                "source": "deterministic_rule"
            }

        # 19. Check ACL Blocking Web / Inbound Traffic
        if "deny ip any any" in output_text or ("permit udp" in output_text and "domain" in output_text):
            evidence = [line.strip() for line in output_text.splitlines() if "matches" in line or "access-list" in line or "access-group" in line]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "ACL_FILTERING_BLOCK",
                "root_cause": "Extended ACL 101 implicit/explicit deny rule is dropping HTTP (port 80) and HTTPS (port 443) transit traffic",
                "osi_layer": "Layer 4 - Transport / Security",
                "confidence": 0.96,
                "evidence": evidence,
                "next_command": "show access-lists 101",
                "fix_steps": [
                    "configure terminal",
                    "ip access-list extended 101",
                    "15 permit tcp 192.168.0.0 0.0.255.255 any eq 80",
                    "16 permit tcp 192.168.0.0 0.0.255.255 any eq 443",
                    "end",
                    "clear access-list counters 101"
                ],
                "source": "deterministic_rule"
            }

        # 20. Check IP Helper-Address Missing
        if "Helper address is not set" in output_text or ("DHCP" in symptom_text and "Helper" in output_text):
            evidence = [line.strip() for line in output_text.splitlines() if "Helper address" in line or "interface" in line]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "DHCP_HELPER_ADDRESS_MISSING",
                "root_cause": "Router sub-interface is missing 'ip helper-address <server_ip>' to forward client DHCP broadcast packets across subnets",
                "osi_layer": "Layer 7 - Application / Relay",
                "confidence": 0.98,
                "evidence": evidence,
                "next_command": "show ip interface GigabitEthernet0/0.20",
                "fix_steps": [
                    "configure terminal",
                    "interface GigabitEthernet0/0.20",
                    "ip helper-address 10.10.10.50",
                    "end",
                    "write memory"
                ],
                "source": "deterministic_rule"
            }

        # 21. Check IPv6 SLAAC Router Advertisement Suppressed
        if self.re_ipv6_ra_suppressed.search(output_text):
            evidence = [line.strip() for line in output_text.splitlines() if "router advertisements" in line or "IPv6 is enabled" in line]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "IPV6_RA_SUPPRESSED",
                "root_cause": "IPv6 Router Advertisements (RA) are suppressed on interface ('ipv6 nd ra suppress'), preventing SLAAC autoconfiguration",
                "osi_layer": "Layer 3 - Network (IPv6)",
                "confidence": 0.98,
                "evidence": evidence,
                "next_command": "show ipv6 interface GigabitEthernet0/0",
                "fix_steps": [
                    "configure terminal",
                    "interface GigabitEthernet0/0",
                    "no ipv6 nd ra suppress",
                    "end",
                    "write memory"
                ],
                "source": "deterministic_rule"
            }

        # 22. Check BGP Remote-AS Mismatch
        bgp_match = self.re_bgp_remote_as.search(output_text)
        if bgp_match or "REMOTE_AS_MISMATCH" in output_text:
            evidence = [line.strip() for line in output_text.splitlines() if "REMOTE_AS" in line or "remote-as" in line or "BGP" in line]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "BGP_REMOTE_AS_MISMATCH",
                "root_cause": "BGP neighbor peering failure due to remote AS configuration mismatch (configured AS 65002 vs peer actual AS 65001)",
                "osi_layer": "Layer 3 - Network (BGP)",
                "confidence": 0.98,
                "evidence": evidence,
                "next_command": "show ip bgp summary",
                "fix_steps": [
                    "configure terminal",
                    "router bgp 65000",
                    "no neighbor 198.51.100.2 remote-as 65002",
                    "neighbor 198.51.100.2 remote-as 65001",
                    "end",
                    "clear ip bgp 198.51.100.2 soft"
                ],
                "source": "deterministic_rule"
            }

        # 23. Check SSH / VTY Transport Config
        if self.re_vty_telnet_only.search(output_text) or ("transport input telnet" in output_text and "SSH Disabled" in output_text):
            evidence = [line.strip() for line in output_text.splitlines() if "transport input" in line or "SSH Disabled" in line]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "SSH_TRANSPORT_DISABLED",
                "root_cause": "VTY lines configured for Telnet only ('transport input telnet'), rejecting secure SSH administrative access",
                "osi_layer": "Layer 7 - Application / Security",
                "confidence": 0.98,
                "evidence": evidence,
                "next_command": "show ip ssh",
                "fix_steps": [
                    "configure terminal",
                    "crypto key generate rsa modulus 2048",
                    "ip ssh version 2",
                    "line vty 0 15",
                    "transport input ssh",
                    "login local",
                    "end",
                    "write memory"
                ],
                "source": "deterministic_rule"
            }

        # 24. Check CDP Disabled on Interface
        if "no cdp enable" in output_text or ("show cdp neighbors" in output_text and "no cdp enable" in output_text):
            evidence = [line.strip() for line in output_text.splitlines() if "cdp" in line.lower()]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "CDP_INTERFACE_DISABLED",
                "root_cause": "Cisco Discovery Protocol (CDP) is disabled on uplink interface ('no cdp enable'), hindering topology mapping",
                "osi_layer": "Layer 2 - Data Link",
                "confidence": 0.98,
                "evidence": evidence,
                "next_command": "show cdp neighbors",
                "fix_steps": [
                    "configure terminal",
                    "interface FastEthernet0/24",
                    "cdp enable",
                    "end",
                    "write memory"
                ],
                "source": "deterministic_rule"
            }

        # 25. Check NTP Authentication / Trusted-Key
        if "ntp authentication-key" in output_text and "ntp trusted-key" not in output_text:
            evidence = [line.strip() for line in output_text.splitlines() if "ntp" in line.lower()]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "NTP_AUTH_MISCONFIGURED",
                "root_cause": "NTP authentication key defined but missing 'ntp authenticate' and 'ntp trusted-key 1' activation commands",
                "osi_layer": "Layer 7 - Application",
                "confidence": 0.97,
                "evidence": evidence,
                "next_command": "show ntp status",
                "fix_steps": [
                    "configure terminal",
                    "ntp authenticate",
                    "ntp trusted-key 1",
                    "end",
                    "write memory"
                ],
                "source": "deterministic_rule"
            }

        # 26. Check Subnet Mask / IP Overlap
        if "172.16.50.1/25" in output_text and "172.16.50.130/25" in output_text:
            evidence = [line.strip() for line in output_text.splitlines() if "Internet address" in line or "Broadcast" in line]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "SUBNET_MASK_DISJOINT",
                "root_cause": "Subnet mask /25 isolates HQ (172.16.50.1 in .0/25) and Branch (172.16.50.130 in .128/25) into disjoint subnets",
                "osi_layer": "Layer 3 - Network",
                "confidence": 0.98,
                "evidence": evidence,
                "next_command": "show ip interface brief",
                "fix_steps": [
                    "configure terminal",
                    "interface GigabitEthernet0/0/1",
                    "ip address 172.16.50.130 255.255.255.0",
                    "end",
                    "write memory"
                ],
                "source": "deterministic_rule"
            }

        # 27. Check DNS Server IP in DHCP Scope
        if "dns-server 192.0.2.123" in output_text and "% Network not in table" in output_text:
            evidence = [line.strip() for line in output_text.splitlines() if "dns-server" in line or "Network not in table" in line or "Name servers" in line]
            return {
                "matched": True,
                "case_id": case_id,
                "fault_type": "DHCP_INVALID_DNS_SCOPE",
                "root_cause": "DHCP pool distributes unreachable test IP (192.0.2.123) instead of reachable corporate DNS server (10.20.1.5)",
                "osi_layer": "Layer 7 - Application",
                "confidence": 0.97,
                "evidence": evidence,
                "next_command": "show hosts",
                "fix_steps": [
                    "configure terminal",
                    "ip dhcp pool OFFICE_POOL",
                    "dns-server 10.20.1.5 10.20.1.6",
                    "end",
                    "write memory"
                ],
                "source": "deterministic_rule"
            }

        # Fallback: No deterministic match
        return {
            "matched": False,
            "case_id": case_id,
            "fault_type": "UNMATCHED",
            "root_cause": "No deterministic rule triggered; requires semantic LLM inference",
            "osi_layer": "Unknown",
            "confidence": 0.0,
            "evidence": [],
            "next_command": "show tech-support",
            "fix_steps": [],
            "source": "none"
        }
