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
To run nsxPyCheck:
1. You have to update NSX Manager credentials in `nsxPyCheck.config` like described above.
2. Run configuration collection.
3. Run configuration check.

Example
```
Step 1: Edit nsxPyCheck.config

Step 2: Run Collection
./nsxPyCheck.py --collect --dir test-nsx --nsxmgr 192.168.0.104 --collect

nsxPyCheck.configetting Nv Edges General Info...
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

Step 3: ./nsxPyCheck.py --collect --dir test-nsx --nsxmgr 192.168.0.104 --check

```










