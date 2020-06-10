# AWS

## script update-aws-security-group

* add/replace permissions in security group to grant access to your external ip
* multiple users can update the security group at the same time
* multiple services can be configured
* ipv4 and ipv6
* uses the computer name to distinguish its rules from those of other users in the security group
* written in PowerShell
* uses AWS Tools for PowerShell

### common settings

```
# update the following parameters: AccessKeyID, SecretAccessKeyID, Region, Ipv4, Ipv6
Param(
  [string]$AccessKeyID="XXXXXXXXXXXXXXXXXXXX",
  [string]$SecretAccessKeyID="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  [string]$Region="us-east-1",
  [string]$SecurityGroup="sg-XXXXXXXXXXXXXXXXXXX",
  [switch]$Ipv4=$true,
  [switch]$Ipv6=$false,
  [switch]$SetAws=$true,
  [switch]$Debug=$true)
```

```
# add/remove services to be configured
$Services = @(
  [pscustomobject]@{Name='HTTP'; FromPort=80; ToPort=80; IpProtocol='tcp'}
  [pscustomobject]@{Name='HTTPS'; FromPort=443; ToPort=443; IpProtocol='tcp'}
  [pscustomobject]@{Name='RDP'; FromPort=3389; ToPort=3389; IpProtocol='tcp'}
  [pscustomobject]@{Name='SSH'; FromPort=6922; ToPort=6922; IpProtocol='tcp'}
)
```
