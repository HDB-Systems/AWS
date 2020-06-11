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
# based on the code available in https://8kmiles.com/blog/powershell-automating-aws-security-groups-2/
#
# HDB Systems <contato@hdbsystems.com.br>
# modified 2020-06-10
#
# -------------------------------------------------------------------------

# update the following parameters: AccessKeyID, SecretAccessKeyID, Region, Ipv4, Ipv6
Param(
  [string]$AccessKeyID="XXXXXXXXXXXXXXXXXXX",
  [string]$SecretAccessKeyID="XXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXXX",
  [string]$Region="us-east-1",
  [string]$SecurityGroup="sg-XXXXXXXXXXXXXXXXX",
  [switch]$Ipv4=$true,
  [switch]$Ipv6=$false,
  [switch]$SetAws=$true,
  [switch]$Debug=$true)

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
  [pscustomobject]@{Name='SSH'; FromPort=22; ToPort=22; IpProtocol='tcp'}
)

# set aws credentials
If($SetAws)
{
  Set-AWSCredentials -AccessKey $InfoObject.AccessKey -SecretKey $InfoObject.SecretKey
  Set-DefaultAWSRegion -Region $InfoObject.Region
}

# get my computer name
$ComputerName = Get-WMIObject Win32_ComputerSystem | Select-Object -ExpandProperty name
If($Debug){ Write-Host "[DEBUG] Computer Name is $($ComputerName)" }

# get my external ipv4
If($Ipv4){ $CidrIpv4 = Invoke-RestMethod https://api.ipify.org?format=json }
If($Ipv4){ If($Debug){ Write-Host "[DEBUG] External Ipv4 is $($CidrIpv4.ip)" } }

# get my external ipv6
If($Ipv6){ $CidrIpv6 = Invoke-RestMethod https://api6.ipify.org?format=json }
If($Ipv6){ If($Debug){ Write-Host "[DEBUG] External Ipv6 is $($CidrIpv6.ip)" } }

# security group to grant/revoke permissions
$SecGroup = Get-EC2SecurityGroup -GroupId $InfoObject.GroupId
If($Debug){ Write-Host "[DEBUG] Security group is $($SecGroup.GroupId) - $($SecGroup.GroupName)" }

# revoke outdated permissions
# Description field equals "ComputerName (*)" and Ip different of MyIp
If($Debug){ Write-Host "[DEBUG] Removing outdated permissions for this computer on security group" }

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
      If($Debug){ Write-Host "[DEBUG]   Revoked IPv4 Rule: FromPort: $($IpPermission.FromPort), ToPort: $($IpPermission.ToPort), IpProtocol: $($IpPermission.IpProtocol), CidrIp: $($Ipv4Range.CidrIp), Description: $($Ipv4Range.Description)" }
      $Done=$true
    }

    $Ipv6RangesList = $IpPermission.Ipv6Ranges | Where-Object {$Ipv6 -and $_.CidrIpv6 -ne "$($CidrIpv6.ip)/128" -and $_.Description -like "$($ComputerName) (*)"}
    ForEach ($Ipv6Range in $Ipv6RangesList)
    {
      # ipv6: revoke rule
      $revokeIpPermission = New-Object Amazon.EC2.Model.IpPermission -Property @{FromPort=$IpPermission.FromPort;ToPort=$IpPermission.ToPort;IpProtocol="$($IpPermission.IpProtocol)";Ipv6Ranges=$Ipv6Range}
      Revoke-EC2SecurityGroupIngress -GroupId $InfoObject.GroupId -IpPermissions $revokeIpPermission
      If($Debug){ Write-Host "[DEBUG]   Revoked IPv6 Rule: FromPort: $($IpPermission.FromPort), ToPort: $($IpPermission.ToPort), IpProtocol: $($IpPermission.IpProtocol), CidrIpv6: $($Ipv6Range.CidrIpv6), Description: $($Ipv6range.Description)" }
      $Done=$true
    }
  }
}
If(!$Done){ If($Debug){ Write-Host "[DEBUG]   no rules to remove" } }

# configure new permissions
If($Debug){ Write-Host "[DEBUG] Configuring new permissions for this computer on security group" }

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
      If($Debug){ Write-Host "[DEBUG]   Added IPv4 Rule: FromPort: $($IpPermission.FromPort), ToPort: $($IpPermission.ToPort), IpProtocol: $($IpPermission.IpProtocol), CidrIp: $($Ipv4Range.CidrIp), Description: $($Ipv4Range.Description)" }
      $Done=$true
    }
    Else
    {
      If($Debug){ Write-Host "[DEBUG]   WARNING: IPv4 Rule Already Exists: FromPort: $($IpPermission.FromPort), ToPort: $($IpPermission.ToPort), IpProtocol: $($IpPermission.IpProtocol), CidrIp: $($Ipv4Range.CidrIp)" }
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
      If($Debug){ Write-Host "[DEBUG]   Added IPv6 Rule: FromPort: $($IpPermission.FromPort), ToPort: $($IpPermission.ToPort), IpProtocol: $($IpPermission.IpProtocol), CidrIpv6: $($Ipv6Range.CidrIpv6), Description: $($Ipv6range.Description)" }
      $Done=$true
    }
    Else
    {
      If($Debug){ Write-Host "[DEBUG]   WARNING: IPv6 Rule Already Exists: FromPort: $($IpPermission.FromPort), ToPort: $($IpPermission.ToPort), IpProtocol: $($IpPermission.IpProtocol), CidrIpv6: $($Ipv6Range.CidrIpv6)" }
    }
  }
}
If(!$Done){ If($Debug){ Write-Host "[DEBUG]   no rules to add" } }
