# 2026-11-07 11:42:50 by RouterOS 7.25.1
# software id = FAKE-0030
#
# model = CRS326-24G-2S+
/interface bridge add arp-inspection=yes dhcp-snooping=yes name=bridge
/interface ethernet switch port set ether2 storm-rate=5
/interface ethernet switch port set ether3 storm-rate=5
/interface bridge port add bridge=bridge interface=sfp-sfpplus1 trusted=yes trusted-arp=yes
/interface bridge port add bpdu-guard=yes bridge=bridge edge=yes frame-types=admit-only-untagged-and-priority-tagged interface=ether2 pvid=10
/interface bridge port add bpdu-guard=yes bridge=bridge edge=yes frame-types=admit-only-untagged-and-priority-tagged interface=ether3 pvid=10
/ip neighbor discovery-settings set discover-interface-list=none
/interface dot1x server add auth-types=dot1x,mac-auth interface=ether2
/interface dot1x server add auth-types=dot1x,mac-auth interface=ether3
/system identity set name=lab-crs-l3
