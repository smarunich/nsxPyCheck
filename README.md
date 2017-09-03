# nsxPyCheck

- nsxPyCheck is NSX Configuration Compliance tool, that includes multiple functions to collect and verify an actual NSX environment to the set of baselines/standards.
The baseline is defined in `nsxPyCheck.config` configuration file.
- Checks include NSX Manager, NSX Controllers, DLRs, ESGs components leveraging NSX API and NSX Central CLI through NSX API.
- nsxPyCheck as well collects configuration of ESGs, DLRs, Logical Switches and Security Tags, Security Groups, Security Policies and DFW ruleset.
The partial backup of configuration can be used with revision control system like SVN or GIT to track changes in the enviroment.
- Tested NSX versions: 6.2.x, 6.3.x

Project inspired by: 

- RANCID: http://www.shrubbery.net/rancid/
- vCheck: http://www.virtu-al.net/vcheck-pluginsheaders/vcheck/
- PyNSXv: https://github.com/vmware/pynsxv

# Dependencies
nsxPyCheck has the following dependencies:
- python3
- jinja2 
- inscriptis
- lxml 
- xmltodict
# Install
- On Debian/Ubuntu:
```apt install git python3 python3-pip
pip3 install jinja2 inscriptis lxml xmltodict
git clone https://github.com/smarunich/nsxPyCheck
```
- On RHEL/CentOS:
```yum install epel-release
yum update
yum install git python34 python34-pip
pip3 install jinja2 inscriptis lxml xmltodict
git clone https://github.com/smarunich/nsxPyCheck
```

- After you installed nsxPyCheck, you have to configure `nsxPyCheck.config` file that contains NSX manager credentials. 

The `nsxPyCheck.config` file has the following format:

```ini
; nsxPyCheck - NSX Configuration Compliance Tool - Configuration Baseline
[General]
;
debugEnabled = false
; UserPass
username = admin
password = VMware1!
; You should not store passwords in plain text
; configuration files.
; password = SECRET
email_report = false
smtp_server = smtp.example.com:25
email_from = nsxPyCheck@nsxPyCheck
email_to = user1@example.com, user2@example.com
; OPTIONAL, automatically commits all the acquired data to SVN
; leveraging svnCommit function with subprocess svn
; versionControlEnabled = SVN
; To disable
; versionControlEnabled = false
versionControlEnabled = false
;
reportJinjaTemplatePath = nsxPyCheckReportTmpl.html
; Configuration collection
collectESGconfigs = true
collectDLRconfigs = true
collectLogicalSWconfigs = true
collectDfwRulesetconfigs = true
collectDfwSecurityTagsconfigs = true
collectDfwSecurityGroupsconfigs = true
collectDfwSecurityPoliciesconfigs = true
collectDfwIpsetconfigs = true
;
```
# HowTo
nsxPyCheck includes three functions:
- `collect` to perform actual configuration collection
- `check` to perform check of already downloaded configuration
- `cli` to run NSX Central CLI against NSX Manager

```
nsxPyCheck - Collect and Check NSX configuration, NSX configuration compliance
tool.

optional arguments:
  -h, --help       show this help message and exit
  --nsxmgr NSXMGR  NSX Manager IP or FQDN.
  --dir DIR        Configuration directory.
  --cli CLI        NSX Central CLI command to run.
  --collect        Perform configuration collection.
  --check          Perform configuration compliance check.
```

- To run nsxPyCheck:

1. You have to update NSX Manager credentials in `nsxPyCheck.config` like described above.
2. Run configuration collection.
```
./nsxPyCheck.py --collect --dir test-nsx --nsxmgr 192.168.0.104 --collect
```
3. Run configuration check.
```
./nsxPyCheck.py --collect --dir test-nsx --nsxmgr 192.168.0.104 --check
```
4. Non-compliant items are saved in $nsxmgr-NSX-PyCheck.report under the defined folder (ex. test-nsx), if the enviroment fully complies to baseline no $nsxmgr-NSX-PyCheck.report will be generated. Report can be send over email as well, please refer to config files to enable it.
```
cat  test-nsx/192.168.0.104-NSX-PyCheck.report
```
5. (Optional) nsxPyCheck allows to execute NSX Central CLI command.
```
./nsxPyCheck.py --nsxmgr 192.168.0.104 --cli "show edge all"
```

# Examples

For reports please refer to `examples` folder.

- Step 1: 
```
Edit nsxPyCheck.config
```

- Step 2: Run Collection

`./nsxPyCheck.py --collect --dir test-nsx --nsxmgr 192.168.0.104 --collect`
```
Getting Nv Edges General Info...
Saving results into: test-nsx/192.168.0.104-GeneralInfoNsxEdges.xml
Getting NSX DLRs configuration...
Generating Edge List...
Reading file: test-nsx/192.168.0.104-GeneralInfoNsxEdges.xml
Saving results into: test-nsx/192.168.0.104-distributedRouter-l2vpn-dlr01-edge-1-config.xml
Saving results into: test-nsx/192.168.0.104-distributedRouter-t2-udlr-edge-f2f1db02-6840-4a0b-ac78-ce25e273bcf1-config.xml
Saving results into: test-nsx/192.168.0.104-distributedRouter-t1-udlr-edge-a3929bae-7d01-4550-94a4-570dfe4e5a09-config.xml
Saving results into: test-nsx/192.168.0.104-distributedRouter-t3-dev-dlr01-edge-10-config.xml
Getting NSX ESGs configuration...
Generating Edge List...
Reading file: test-nsx/192.168.0.104-GeneralInfoNsxEdges.xml
Saving results into: test-nsx/192.168.0.104-gatewayServices-l2vpn-server-edge-2-config.xml
Saving results into: test-nsx/192.168.0.104-gatewayServices-t1-edge1-edge-3-config.xml
Saving results into: test-nsx/192.168.0.104-gatewayServices-t2-edge-edge-4-config.xml
Saving results into: test-nsx/192.168.0.104-gatewayServices-t1-app1-web-lb-edge-5-config.xml
Saving results into: test-nsx/192.168.0.104-gatewayServices-t1-app1-app-lb-edge-6-config.xml
Saving results into: test-nsx/192.168.0.104-gatewayServices-t3-ecmp01-edge-7-config.xml
Saving results into: test-nsx/192.168.0.104-gatewayServices-t3-ecmp02-edge-8-config.xml
Saving results into: test-nsx/192.168.0.104-gatewayServices-t3-dev-edge01-edge-9-config.xml
Saving results into: test-nsx/192.168.0.104-gatewayServices-t3-dev-lb01-edge-11-config.xml
Getting NSX Logical Switches configuration...
Saving results into: test-nsx/192.168.0.104-logical-switches-config.xml
Getting NSX DFW Ruleset configuration...
Saving results into: test-nsx/192.168.0.104-dfw-config.xml
Getting NSX DFW Security Groups configuration...
Saving results into: test-nsx/192.168.0.104-nsx-security-groups-config.xml
Getting NSX DFW Security Tags configuration...
Saving results into: test-nsx/192.168.0.104-nsx-security-tags-config.xml
Getting NSX DFW Security Policies configuration...
Saving results into: test-nsx/192.168.0.104-nsx-security-policies-config.xml
Getting NSX DFW IPsets configuration...
Saving results into: test-nsx/192.168.0.104-nsx-ipsets-config.xml
```

- Step 3: Run Checks
`./nsxPyCheck.py --collect --dir test-nsx --nsxmgr 192.168.0.104 --check`

```
Converting Edge IDs to Edge Names...
Checking NSX Edge BGP Neighbors state...
Checking NSX ESG Interfaces Configuration...
Reading file: test-nsx/192.168.0.104-distributedRouter-t2-udlr-edge-f2f1db02-6840-4a0b-ac78-ce25e273bcf1-config.xml
Checking NSX Edge Syslog Configuration...
Checking NSX Edge Firewall Configuration...
Checking General NSX Edge Routing Configuration...
Checking NSX Edge Routing Static Routing Configuration...
Checking NSX Edge OSPF Configuration...
Checking NSX Edge BGP Configuration...
Converting Edge IDs to Edge Names...
Checking NSX Edge BGP Neighbors state...
Checking NSX DHCP Relay Configuration...
Checking NSX DLR Interfaces Configuration...
Reading file: test-nsx/192.168.0.104-gatewayServices-t1-edge1-edge-3-config.xml
Checking NSX Edge Syslog Configuration...
Checking NSX Edge Firewall Configuration...
Checking General NSX Edge Routing Configuration...
Checking NSX Edge OSPF Configuration...
Checking NSX Edge BGP Configuration...
```
- Step 4: Inspect Report
`cat test-nsx/192.168.0.104-NSX-PyCheck.report`
```

nsxPyCheck Report(s) for Saturday, 02. September 2017 11:50PM


NSX Manager: all configuration items (CIs) out of compliance with a baseline.

* NTP server is not set or NTP Misconfigured: 1 9 2 . 1 6 8 . 0 . 9
* Syslog server is not set or Syslog Misconfigured: 192.168.0.130 514 UDP
* NSX Manager connection to vCenter is down.

NSX Prepared Host CP Communication Status: all configuration items (CIs) out of compliance with a baseline.

* 192.168.0.101:Compute-A host communication issue: nsxMgrToFirewallAgentConn:DOWN nsxMgrToControlPlaneAgentConn:DOWN hostToControllerConn:NOT_AVAILABLE
* 192.168.0.102:Compute-A host communication issue: nsxMgrToFirewallAgentConn:DOWN nsxMgrToControlPlaneAgentConn:DOWN hostToControllerConn:NOT_AVAILABLE

GENERAL EDGE: Appliance Size, Cluster location, HA configuration, Appliance Version and Edge state: all configuration items (CIs) out of compliance with a baseline.

* l2vpn-dlr01 compact 60U2NSX625-A 1 6.2.7 GREEN
* l2vpn-server large 60U2NSX625-A 1 6.2.7 GREEN
* t2-udlr compact 60U2NSX625-A 2 6.2.7 GREEN
* t1-edge1 compact 60U2NSX625-A 2 6.2.7 GREEN
* t1-udlr compact 60U2NSX625-A 2 6.2.7 GREEN
* t2-edge compact 60U2NSX625-A 2 6.2.7 GREEN
* t1-app1-web-lb compact 60U2NSX625-A 1 6.2.7 GREEN
* t1-app1-app-lb compact 60U2NSX625-A 1 6.2.7 GREEN
* t3-ecmp01 compact vol2-dc-a 1 6.2.7 GREEN
* t3-ecmp02 compact vol2-dc-a 1 6.2.7 GREEN
* t3-dev-edge01 compact NOT DEPLOYED 1 6.2.7 RED
* t3-dev-dlr01 compact vol2-dc-a 1 6.2.7 GREEN
* t3-dev-lb01 compact vol2-dc-a 1 6.2.7 GREEN

NSX Edge Syslog: all configuration items (CIs) out of compliance with a baseline.

* l2vpn-dlr01 Syslog is not configured.
* l2vpn-server Syslog is not configured.
* t2-udlr Syslog is not configured.
* t1-edge1 Syslog is not configured.
* t1-udlr Syslog is not configured.
* t2-edge Syslog is not configured.
* t1-app1-web-lb 3 true udp 192.168.0.130
* t1-app1-app-lb Syslog is not configured.
* t3-ecmp01 4 true udp 192.168.0.130
* t3-ecmp02 3 true udp 192.168.0.130
* t3-dev-edge01 3 true udp 192.168.0.130
* t3-dev-dlr01 3 true udp 192.168.0.130
* t3-dev-lb01 3 true udp 192.168.0.130

NSX Edge Appliance Firewall: all configuration items (CIs) out of compliance with a baseline.

* l2vpn-dlr01 NSX Edge Appliance Firewall state is misconfigured. Firewall State Enabled: true
* t2-udlr NSX Edge Appliance Firewall state is misconfigured. Firewall State Enabled: true
* t1-udlr NSX Edge Appliance Firewall state is misconfigured. Firewall State Enabled: true
* t2-edge NSX Edge Appliance Firewall state is misconfigured. Firewall State Enabled: true
* t1-app1-web-lb NSX Edge Appliance Firewall state is misconfigured. Firewall State Enabled: true
* t1-app1-app-lb NSX Edge Appliance Firewall state is misconfigured. Firewall State Enabled: true
* t3-dev-edge01 NSX Edge Appliance Firewall state is misconfigured. Firewall State Enabled: true
* t3-dev-dlr01 NSX Edge Appliance Firewall state is misconfigured. Firewall State Enabled: true
* t3-dev-lb01 NSX Edge Appliance Firewall state is misconfigured. Firewall State Enabled: true

NSX General Routing: all configuration items (CIs) out of compliance with a baseline.

* l2vpn-dlr01 ECMP State Enabled: false
* l2vpn-dlr01 Routing Logging State Enabled: false
* l2vpn-server ECMP State Enabled: false
* l2vpn-server Routing Logging State Enabled: false
* t2-udlr ECMP State Enabled: false
* t1-udlr ECMP State Enabled: false
* t1-udlr Routing Logging State Enabled: false
* t2-edge ECMP State Enabled: false
* t1-app1-web-lb ECMP State Enabled: false
* t1-app1-web-lb Routing Logging State Enabled: false
* t1-app1-app-lb ECMP State Enabled: false
* t1-app1-app-lb Routing Logging State Enabled: false
* t3-dev-dlr01 ECMP State Enabled: false
* t3-dev-lb01 ECMP State Enabled: false
* t3-dev-lb01 Routing Logging State Enabled: false
 l2vpn-dlr01 ['0.0.0.0/0'] Route is missing.
* t2-udlr ['0.0.0.0/0'] Route is missing.
* t1-udlr ['0.0.0.0/0'] Route is missing.
* t3-dev-dlr01 ['0.0.0.0/0'] Route is missing.

NSX BGP: all configuration items (CIs) out of compliance with a baseline.

* BGP is disabled.
* BGP is disabled.
* t1-edge1 Neighbor: 10.1.105.1 BGP holdDown timer is misconfigured.
* t1-edge1 Neighbor: 10.1.105.1 BGP keepAliveTimer is misconfigured.
* t1-edge1 Neighbor: 10.1.105.1 BGP Password is not set.
* t1-edge1 Neighbor: 10.1.11.4 BGP holdDown timer is misconfigured.
* t1-edge1 Neighbor: 10.1.11.4 BGP keepAliveTimer is misconfigured.
* t1-edge1 Neighbor: 10.1.11.4 BGP Password is not set.
* BGP Redistribution is misconfigured.
* t2-edge Neighbor: 10.1.105.1 BGP holdDown timer is misconfigured.
* t2-edge Neighbor: 10.1.105.1 BGP keepAliveTimer is misconfigured.
* t2-edge Neighbor: 10.1.105.1 BGP Password is not set.
* t2-edge Neighbor: 10.1.12.4 BGP holdDown timer is misconfigured.
* t2-edge Neighbor: 10.1.12.4 BGP keepAliveTimer is misconfigured.
* t2-edge Neighbor: 10.1.12.4 BGP Password is not set.
* BGP Redistribution is misconfigured.
* BGP is disabled.
* BGP is disabled.
* t3-ecmp01 Neighbor: 10.1.105.1 BGP holdDown timer is misconfigured.
* t3-ecmp01 Neighbor: 10.1.105.1 BGP keepAliveTimer is misconfigured.
* t3-ecmp01 Neighbor: 10.1.105.1 BGP Password is not set.
* t3-ecmp01 Neighbor: 10.1.13.3 BGP holdDown timer is misconfigured.
* t3-ecmp01 Neighbor: 10.1.13.3 BGP keepAliveTimer is misconfigured.
* t3-ecmp01 Neighbor: 10.1.13.3 BGP Password is not set.
* t3-ecmp01 BGP defaultOriginate is enabled.
* t3-ecmp02 Neighbor: 10.1.105.1 BGP holdDown timer is misconfigured.
* t3-ecmp02 Neighbor: 10.1.105.1 BGP keepAliveTimer is misconfigured.
* t3-ecmp02 Neighbor: 10.1.105.1 BGP Password is not set.
* t3-ecmp02 Neighbor: 10.1.13.3 BGP holdDown timer is misconfigured.
* t3-ecmp02 Neighbor: 10.1.13.3 BGP keepAliveTimer is misconfigured.
* t3-ecmp02 Neighbor: 10.1.13.3 BGP Password is not set.
* t3-ecmp02 BGP defaultOriginate is enabled.
* t3-dev-edge01 Neighbor: 172.16.30.4 BGP holdDown timer is misconfigured.
* t3-dev-edge01 Neighbor: 172.16.30.4 BGP keepAliveTimer is misconfigured.
* t3-dev-edge01 Neighbor: 172.16.30.4 BGP Password is not set.
* t3-dev-edge01 Neighbor: 10.1.13.1 BGP holdDown timer is misconfigured.
* t3-dev-edge01 Neighbor: 10.1.13.1 BGP keepAliveTimer is misconfigured.
* t3-dev-edge01 Neighbor: 10.1.13.1 BGP Password is not set.
* t3-dev-edge01 Neighbor: 10.1.13.2 BGP holdDown timer is misconfigured.
* t3-dev-edge01 Neighbor: 10.1.13.2 BGP keepAliveTimer is misconfigured.
* t3-dev-edge01 Neighbor: 10.1.13.2 BGP Password is not set.
* t3-dev-edge01 BGP Redistribution is misconfigured. BGP to Static.
* BGP is disabled.

NSX DHCP Relay: all configuration items (CIs) out of compliance with a baseline.

* l2vpn-dlr01 DHCP Relay is not configured.
* t2-udlr DHCP Relay is not configured.
* t1-udlr DHCP Relay is not configured.
* t3-dev-dlr01 DHCP Secondary Relay is missing.

NSX DLR Interfaces: all configuration items (CIs) out of compliance with a baseline.

* l2vpn-dlr01 web MTU size misconfiguration or Interface is not Connected.
* l2vpn-dlr01 app MTU size misconfiguration or Interface is not Connected.
* l2vpn-dlr01 db MTU size misconfiguration or Interface is not Connected.
* l2vpn-dlr01 Number of uplinks is not matching the DLR standard. Expected: 1 Actual: 0
* t2-udlr uplink MTU size misconfiguration or Interface is not Connected.
* t2-udlr web MTU size misconfiguration or Interface is not Connected.
* t2-udlr app MTU size misconfiguration or Interface is not Connected.
* t2-udlr db MTU size misconfiguration or Interface is not Connected.
* t1-udlr uplink MTU size misconfiguration or Interface is not Connected.
* t1-udlr web MTU size misconfiguration or Interface is not Connected.
* t1-udlr app MTU size misconfiguration or Interface is not Connected.
* t1-udlr db MTU size misconfiguration or Interface is not Connected.
* t3-dev-dlr01 uplink MTU size misconfiguration or Interface is not Connected.
* t3-dev-dlr01 web MTU size misconfiguration or Interface is not Connected.
* t3-dev-dlr01 app MTU size misconfiguration or Interface is not Connected.
* t3-dev-dlr01 db MTU size misconfiguration or Interface is not Connected.

NSX ESG Interfaces: all configuration items (CIs) out of compliance with a baseline.

* l2vpn-server uplink MTU size misconfiguration. Expected: 9000 Actual: 1500
* l2vpn-server vnic1 MTU size misconfiguration. Expected: 9000 Actual: 1600
* l2vpn-server Number of uplinks is not matching the ESG standard. Expected: 2 Actual: 1
* t1-edge1 uplink MTU size misconfiguration. Expected: 9000 Actual: 1500
* t1-edge1 downlink MTU size misconfiguration. Expected: 9000 Actual: 1500
* t1-edge1 Number of uplinks is not matching the ESG standard. Expected: 2 Actual: 1
* t2-edge uplink MTU size misconfiguration. Expected: 9000 Actual: 1500
* t2-edge downlink MTU size misconfiguration. Expected: 9000 Actual: 1500
* t2-edge Number of uplinks is not matching the ESG standard. Expected: 2 Actual: 1
* t1-app1-web-lb web MTU size misconfiguration. Expected: 9000 Actual: 1500
* t1-app1-web-lb Number of uplinks is not matching the ESG standard. Expected: 2 Actual: 1
* t1-app1-app-lb app MTU size misconfiguration. Expected: 9000 Actual: 1500
* t1-app1-app-lb Number of uplinks is not matching the ESG standard. Expected: 2 Actual: 0
* t3-ecmp01 uplink MTU size misconfiguration. Expected: 9000 Actual: 1500
* t3-ecmp01 t3-dev MTU size misconfiguration. Expected: 9000 Actual: 1500
* t3-ecmp01 t3-dev SendRedirects misconfiguration. Expected: false Actual: true
* t3-ecmp01 Number of uplinks is not matching the ESG standard. Expected: 2 Actual: 1
```
- Step 5 (Optional): Run NSX Central CLI
`./nsxPyCheck.py --nsxmgr 192.168.0.104 --cli "show edge all"`
```
./nsxPyCheck.py --nsxmgr 192.168.0.104 --cli "show edge all"
NOTE: CLI commands for Edge ServiceGateway(ESG) start with 'show edge'
      CLI commands for Distributed Logical Router(DLR) Control VM start with 'show edge'
      CLI commands for Distributed Logical Router(DLR) start with 'show logical-router'
      Edges with version >= 6.2 support Central CLI and are listed here
Legend:
Edge Size: Compact - C, Large - L, X-Large - X, Quad-Large - Q
Edge ID                                    Name                     Size Version Status
edge-1                                     l2vpn-dlr01              C    6.2.7   GREEN
edge-2                                     l2vpn-server             L    6.2.7   GREEN
edge-f2f1db02-6840-4a0b-ac78-ce25e273bcf1  t2-udlr                  C    6.2.7   GREEN
edge-3                                     t1-edge1                 C    6.2.7   GREEN
edge-a3929bae-7d01-4550-94a4-570dfe4e5a09  t1-udlr                  C    6.2.7   GREEN
edge-4                                     t2-edge                  C    6.2.7   GREEN
edge-5                                     t1-app1-web-lb           C    6.2.7   GREEN
edge-6                                     t1-app1-app-lb           C    6.2.7   GREEN
edge-7                                     t3-ecmp01                C    6.2.7   GREEN
edge-8                                     t3-ecmp02                C    6.2.7   GREEN
edge-9                                     t3-dev-edge01            C    6.2.7   RED
edge-10                                    t3-dev-dlr01             C    6.2.7   GREEN
edge-11                                    t3-dev-lb01              C    6.2.7   GREEN
```





