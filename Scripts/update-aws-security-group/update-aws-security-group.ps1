# ------------------------------------------------------------------------
# This script is licensed under GNU GPL version 3.0 or above
# -------------------------------------------------------------------------
# This program is free software: you can redistribute it and/or modify
# it under the terms of the GNU General Public License as published by
# the Free Software Foundation, either version 3 of the License, or
# (at your option) any later version.
#
# This program is distributed in the hope that it will be useful,
# but WITHOUT ANY WARRANTY; without even the implied warranty of
# MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
# GNU General Public License for more details.
#
# You should have received a copy of the GNU General Public License
# along with this program.  If not, see <http://www.gnu.org/licenses/>.
#
# USAGE: update-aws-security-group.ps1 -AccessKeyID "XXXXXXXXXXXXXXXXXXXX" -SecretAccessKeyID "XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX" -Region "xx-xxxx-x" -SecurityGroup "sg-XXXXXXXXXXXXXXXXX" -Ipv4 -Ipv6 -Verbose
#
# HDB Systems <contato@hdbsystems.com.br>
# modified 2020-07-05
#
# -------------------------------------------------------------------------

# parameters
Param(
  [string]$AccessKeyID,
  [string]$SecretAccessKeyID,
  [string]$Region,
  [string]$SecurityGroup,
  [switch]$Ipv4,
  [switch]$Ipv6,
  [switch]$Verbose
)

$InfoObject = New-Object PSObject -Property @{
  AccessKey = $AccessKeyID
  SecretKey = $SecretAccessKeyID
  Region = $Region
  GroupId = $SecurityGroup
}

# add/remove services to be configured
$Services = @(
  [pscustomobject]@{Name='HTTP'; FromPort=80; ToPort=80; IpProtocol='tcp'}
  [pscustomobject]@{Name='HTTPS'; FromPort=443; ToPort=443; IpProtocol='tcp'}
  [pscustomobject]@{Name='RDP'; FromPort=3389; ToPort=3389; IpProtocol='tcp'}
  [pscustomobject]@{Name='SSH'; FromPort=6922; ToPort=6922; IpProtocol='tcp'}
)

# timestamp
$Timestamp = Get-Date -Format "dddd dd/MM/yyyy HH:mm K"
# script dir and filename (without extension)
$ScriptDir = (Get-Item $PSCommandPath).DirectoryName
$ScriptBasename = (Get-Item $PSCommandPath).Basename
# log file
$LogFile = "$($ScriptDir)\$($ScriptBasename).log"

# log function
Function Log ($Message) {
  If($Verbose){ Write-Host "$($Message)" }
  Add-Content $LogFile $Message
}

# removing previous log
If(Test-Path $LogFile){ Remove-Item $LogFile }

# init
Log "Executing script on $($Timestamp)"
Log " "

# mandatory parameters
If(!($AccessKeyID -and $SecretAccessKeyID -and $Region -and $SecurityGroup)){ Throw "You must supply a value for -AccessKeyID, -SecretAccessKeyID, -Region and -SecurityGroup parameters" }

# validating parms
If (!($Ipv4 -or $Ipv6)) { Throw "You must supply -Ipv4 and/or -Ipv6 parameters" } 

# setting aws info
# credential
Set-AWSCredentials -AccessKey $InfoObject.AccessKey -SecretKey $InfoObject.SecretKey
Log "Setting AWS credential $($InfoObject.AccessKey)"
# region
Set-DefaultAWSRegion -Region $InfoObject.Region
Log "Setting AWS region to $($InfoObject.Region)"
# security group to grant/revoke permissions
$SecGroup = Get-EC2SecurityGroup -GroupId $InfoObject.GroupId
Log "Setting AWS security group to $($SecGroup.GroupId) - $($SecGroup.GroupName)"
Log " "

# get my computer name
$ComputerName = Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty name
Log "Computer name is $($ComputerName)"

# get my external ipv4
If($Ipv4){ $CidrIpv4 = Invoke-RestMethod https://api.ipify.org?format=json }
If($Ipv4){ Log "External Ipv4 is $($CidrIpv4.ip)" }

# get my external ipv6
If($Ipv6){ $CidrIpv6 = Invoke-RestMethod https://api6.ipify.org?format=json }
If($Ipv6){ Log "External Ipv6 is $($CidrIpv6.ip)" }
Log " "

# revoke outdated permissions
# Description field equals "ComputerName (*)" and Ip different of MyIp
Log "Removing outdated permissions for this computer on security group"

$Done=$false

ForEach ($Service in $Services)
{
  $IpPermissionsList = $SecGroup.IpPermissions | Where-Object {$_.FromPort -eq $Service.FromPort -and $_.ToPort -eq $Service.ToPort -and $_.IpProtocol -eq "$($Service.IpProtocol)"}

  ForEach ($IpPermission in $IpPermissionsList)
  {
    $Ipv4RangesList = $IpPermission.Ipv4Ranges | Where-Object {$Ipv4 -and $_.CidrIp -ne "$($CidrIpv4.ip)/32" -and $_.Description -like "$($ComputerName) (*)"}
    ForEach ($Ipv4Range in $Ipv4RangesList)
    {
      # ipv4: revoke rule
      $revokeIpPermission = New-Object Amazon.EC2.Model.IpPermission -Property @{FromPort=$IpPermission.FromPort;ToPort=$IpPermission.ToPort;IpProtocol="$($IpPermission.IpProtocol)";Ipv4Ranges=$Ipv4Range}
      Revoke-EC2SecurityGroupIngress -GroupId $InfoObject.GroupId -IpPermissions $revokeIpPermission
      Log "  Revoked Ipv4 rule: FromPort: $($IpPermission.FromPort), ToPort: $($IpPermission.ToPort), IpProtocol: $($IpPermission.IpProtocol), CidrIp: $($Ipv4Range.CidrIp), Description: $($Ipv4Range.Description)"
      $Done=$true
    }

    $Ipv6RangesList = $IpPermission.Ipv6Ranges | Where-Object {$Ipv6 -and $_.CidrIpv6 -ne "$($CidrIpv6.ip)/128" -and $_.Description -like "$($ComputerName) (*)"}
    ForEach ($Ipv6Range in $Ipv6RangesList)
    {
      # ipv6: revoke rule
      $revokeIpPermission = New-Object Amazon.EC2.Model.IpPermission -Property @{FromPort=$IpPermission.FromPort;ToPort=$IpPermission.ToPort;IpProtocol="$($IpPermission.IpProtocol)";Ipv6Ranges=$Ipv6Range}
      Revoke-EC2SecurityGroupIngress -GroupId $InfoObject.GroupId -IpPermissions $revokeIpPermission
      Log "  Revoked Ipv6 rule: FromPort: $($IpPermission.FromPort), ToPort: $($IpPermission.ToPort), IpProtocol: $($IpPermission.IpProtocol), CidrIpv6: $($Ipv6Range.CidrIpv6), Description: $($Ipv6range.Description)"
      $Done=$true
    }
  }
}
If(!$Done){ Log "  no rules to remove" }

# configure new permissions
Log "Configuring new permissions for this computer on security group"

$IpPermissionsList = New-Object System.Collections.ArrayList

ForEach ($Service in $Services)
{
  # ipv4: configure rule
  $newIpv4Range = New-Object Amazon.EC2.Model.IpRange -Property @{CidrIp="$($CidrIpv4.ip)/32";Description="$($ComputerName) ($($Service.Name))"}
  $newIpPermission = New-Object Amazon.EC2.Model.IpPermission -Property @{IpProtocol="$($Service.IpProtocol)";FromPort=$Service.FromPort;ToPort=$Service.ToPort;Ipv4Ranges=$newIpv4Range}
  If($Ipv4){ [void]$IpPermissionsList.Add($newIpPermission) }
  # ipv6: configure rule
  $newIpv6Range = New-Object Amazon.EC2.Model.Ipv6Range -Property @{CidrIpv6="$($CidrIpv6.ip)/128";Description="$($ComputerName) ($($Service.Name))"}
  $newIpPermission = New-Object Amazon.EC2.Model.IpPermission -Property @{IpProtocol="$($Service.IpProtocol)";FromPort=$Service.FromPort;ToPort=$Service.ToPort;Ipv6Ranges=$newIpv6Range}
  If($Ipv6){ [void]$IpPermissionsList.Add($newIpPermission) }
}

# grant permissions
$Done=$false

ForEach ($IpPermission in $IpPermissionsList)
{
  $Ipv4RangesList = $IpPermission.Ipv4Ranges
  ForEach ($Ipv4Range in $Ipv4RangesList)
  {
    # verify if rule already exists
    $existIpPermission = $SecGroup.IpPermissions | Where-Object {$_.FromPort -eq $IpPermission.FromPort -and $_.ToPort -eq $IpPermission.ToPort -and $_.IpProtocol -eq "$($IpPermission.IpProtocol)" -and $_.Ipv4Ranges.CidrIp -eq $Ipv4Range.CidrIp}
    If(!$existIpPermission.Count -gt 0)
    {
      # ipv4: grant rule
      $grantIpPermission = New-Object Amazon.EC2.Model.IpPermission -Property @{FromPort=$IpPermission.FromPort;ToPort=$IpPermission.ToPort;IpProtocol="$($IpPermission.IpProtocol)";Ipv4Ranges=$Ipv4Range}
      Grant-EC2SecurityGroupIngress -GroupId $InfoObject.GroupId -IpPermissions $grantIpPermission
      Log "  Added Ipv4 rule: FromPort: $($IpPermission.FromPort), ToPort: $($IpPermission.ToPort), IpProtocol: $($IpPermission.IpProtocol), CidrIp: $($Ipv4Range.CidrIp), Description: $($Ipv4Range.Description)"
      $Done=$true
    }
    Else
    {
      Log "  WARNING: Ipv4 rule already exists: FromPort: $($IpPermission.FromPort), ToPort: $($IpPermission.ToPort), IpProtocol: $($IpPermission.IpProtocol), CidrIp: $($Ipv4Range.CidrIp)"
    }
  }

  $Ipv6RangesList = $IpPermission.Ipv6Ranges
  ForEach ($Ipv6Range in $Ipv6RangesList)
  {
    # verify if rule already exists
    $existIpPermission = $SecGroup.IpPermissions | Where-Object {$_.FromPort -eq $IpPermission.FromPort -and $_.ToPort -eq $IpPermission.ToPort -and $_.IpProtocol -eq "$($IpPermission.IpProtocol)" -and $_.Ipv6Ranges.CidrIpv6 -eq $Ipv6Range.CidrIpv6}
    If(!$existIpPermission.Count -gt 0)
    {
      # ipv6: grant rule
      $grantIpPermission = New-Object Amazon.EC2.Model.IpPermission -Property @{FromPort=$IpPermission.FromPort;ToPort=$IpPermission.ToPort;IpProtocol="$($IpPermission.IpProtocol)";Ipv6Ranges=$Ipv6Range}
      Grant-EC2SecurityGroupIngress -GroupId $InfoObject.GroupId -IpPermissions $grantIpPermission
      Log "  Added Ipv6 rule: FromPort: $($IpPermission.FromPort), ToPort: $($IpPermission.ToPort), IpProtocol: $($IpPermission.IpProtocol), CidrIpv6: $($Ipv6Range.CidrIpv6), Description: $($Ipv6range.Description)"
      $Done=$true
    }
    Else
    {
      Log "  WARNING: Ipv6 rule already exists: FromPort: $($IpPermission.FromPort), ToPort: $($IpPermission.ToPort), IpProtocol: $($IpPermission.IpProtocol), CidrIpv6: $($Ipv6Range.CidrIpv6)"
    }
  }
}
If(!$Done){ Log "  no rules to add" }
