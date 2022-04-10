# AWS

## script update-aws-security-group

* add/replace permissions in security group to grant access to your external ip
* multiple users can update the security group at the same time
* multiple services can be configured
* ipv4 and ipv6
* uses the computer name to distinguish its rules from those of other users in the security group
* written in PowerShell
* uses AWS Tools for PowerShell

### steps to install

* Configure policy with correct security group
* On AWS create a IAM user and attach inline policy
* Configure script (security group, access key, secret key, region, services ...)
* Execute PowerShell as Administrator and execute the commands bellow

```
# Install AWS Tools for PowerShell
# Change execution policy to RemoteSigned
> Install-Module -name AWSPowerShell.NetCore
> Set-ExecutionPolicy -ExecutionPolicy RemoteSigned
```

### how to run the script automatically?
* Create a task in Windows Scheduler
* Add event trigger Microsoft-Windows-NetworkProfile/Operational, with Source=NetworkProfile and EventId=10000
* Add action to execute powershell script
```
  # update the following parameters: AccessKeyID, SecretAccessKeyID, Region, Ipv4, Ipv6
  program/script=powershell
  args=-ExecutionPolicy Bypass C:\Users\Public\update-aws-security-group.ps1 -AccessKeyID 'xxxxxxxxxxxxxxxxxxxx' -SecretAccessKeyID 'xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx' -Region 'xx-xxxx-x' -SecurityGroup 'sg-xxxxxxxxxxxxxxxxx' -Ipv4 -Verbose
  start on=C:\Users\Public\
```
* Put powershell script on C:\Users\Public\

The task will be performed whenever you connect to the internet

### configuration

```
# sets security group on IAM user policy
      "Resource": [
        "arn:aws:ec2:*:*:security-group/sg-XXXXXXXXXXXXXXXXX"
      ]
```

```
# add/remove services to be configured (inside script)
$Services = @(
  [pscustomobject]@{Name='HTTP'; FromPort=80; ToPort=80; IpProtocol='tcp'}
  [pscustomobject]@{Name='HTTPS'; FromPort=443; ToPort=443; IpProtocol='tcp'}
  [pscustomobject]@{Name='RDP'; FromPort=3389; ToPort=3389; IpProtocol='tcp'}
  [pscustomobject]@{Name='SSH'; FromPort=22; ToPort=22; IpProtocol='tcp'}
)
```
