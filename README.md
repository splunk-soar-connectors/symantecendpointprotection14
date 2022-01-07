[comment]: # "Auto-generated SOAR connector documentation"
# Symantec Endpoint Protection 14

Publisher: Splunk  
Connector Version: 2\.1\.6  
Product Vendor: Symantec  
Product Name: Symantec Endpoint Protection 14  
Product Version Supported (regex): "14\.\*"  
Minimum Product Version: 5\.0\.0  

Integrate with Symantec Endpoint Protection 14 to execute investigative, containment, and corrective actions

[comment]: # " File: readme.md"
[comment]: # "  Copyright (c) 2017-2021 Splunk Inc."
[comment]: # ""
[comment]: # "Licensed under the Apache License, Version 2.0 (the 'License');"
[comment]: # "you may not use this file except in compliance with the License."
[comment]: # "You may obtain a copy of the License at"
[comment]: # ""
[comment]: # "    http://www.apache.org/licenses/LICENSE-2.0"
[comment]: # ""
[comment]: # "Unless required by applicable law or agreed to in writing, software distributed under"
[comment]: # "the License is distributed on an 'AS IS' BASIS, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,"
[comment]: # "either express or implied. See the License for the specific language governing permissions"
[comment]: # "and limitations under the License."
[comment]: # ""
The configured user's account must be a System Administrator.


### Configuration Variables
The below configuration variables are required for this Connector to operate.  These variables are specified when configuring a Symantec Endpoint Protection 14 asset in SOAR.

VARIABLE | REQUIRED | TYPE | DESCRIPTION
-------- | -------- | ---- | -----------
**url** |  required  | string | Server URL \(e\.g\. https\://10\.10\.10\.10\:8446\)
**verify\_server\_cert** |  optional  | boolean | Verify server certificate
**username** |  required  | string | System Administrator Username
**password** |  required  | password | Password

### Supported Actions  
[test connectivity](#action-test-connectivity) - Validate credentials provided for connectivity  
[list domains](#action-list-domains) - List all of the administrative domains configured on the device  
[list groups](#action-list-groups) - List all of the administrative groups configured on the device  
[list endpoints](#action-list-endpoints) - List all the endpoints/sensors configured on the device  
[get system info](#action-get-system-info) - Gets the information about the computers in a specified domain  
[get status](#action-get-status) - Get command status report  
[unquarantine device](#action-unquarantine-device) - Unquarantine the endpoint  
[quarantine device](#action-quarantine-device) - Quarantine the endpoint  
[unblock hash](#action-unblock-hash) - Unblock hashes on endpoints  
[block hash](#action-block-hash) - Block hashes on endpoints  
[scan endpoint](#action-scan-endpoint) - Scan an endpoint  
[full scan](#action-full-scan) - Scan a computer  

## action: 'test connectivity'
Validate credentials provided for connectivity

Type: **test**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
No Output  

## action: 'list domains'
List all of the administrative domains configured on the device

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.administratorCount | numeric | 
action\_result\.data\.\*\.companyName | string | 
action\_result\.data\.\*\.contactInfo | string | 
action\_result\.data\.\*\.createdTime | numeric | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.enable | boolean | 
action\_result\.data\.\*\.id | string | 
action\_result\.data\.\*\.name | string |  `symantec admin domain` 
action\_result\.summary\.total\_domains | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list groups'
List all of the administrative groups configured on the device

Type: **investigate**  
Read only: **True**

#### Action Parameters
No parameters are required for this action

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.data\.\*\.childGroups | string | 
action\_result\.data\.\*\.created | numeric | 
action\_result\.data\.\*\.createdBy | string | 
action\_result\.data\.\*\.customIpsNumber | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.domain\.id | string |  `md5` 
action\_result\.data\.\*\.domain\.name | string |  `symantec admin domain` 
action\_result\.data\.\*\.fullPathName | string | 
action\_result\.data\.\*\.id | string |  `symantec group id` 
action\_result\.data\.\*\.lastModified | numeric | 
action\_result\.data\.\*\.name | string | 
action\_result\.data\.\*\.numberOfPhysicalComputers | numeric | 
action\_result\.data\.\*\.numberOfRegisteredUsers | numeric | 
action\_result\.data\.\*\.policyDate | numeric | 
action\_result\.data\.\*\.policyInheritanceEnabled | boolean | 
action\_result\.data\.\*\.policySerialNumber | string | 
action\_result\.summary\.total\_groups | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'list endpoints'
List all the endpoints/sensors configured on the device

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**admin\_domain** |  required  | Administrative domain of the endpoints to query | string |  `symantec admin domain` 
**limit** |  optional  | Maximum number of endpoints to be fetched | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.admin\_domain | string |  `symantec admin domain` 
action\_result\.parameter\.limit | numeric | 
action\_result\.data\.\*\.agentId | string |  `md5` 
action\_result\.data\.\*\.agentTimeStamp | numeric | 
action\_result\.data\.\*\.agentType | string | 
action\_result\.data\.\*\.agentUsn | numeric | 
action\_result\.data\.\*\.agentVersion | string | 
action\_result\.data\.\*\.apOnOff | numeric | 
action\_result\.data\.\*\.atpDeviceId | string | 
action\_result\.data\.\*\.atpServer | string | 
action\_result\.data\.\*\.attributeExtension | string | 
action\_result\.data\.\*\.avEngineOnOff | numeric | 
action\_result\.data\.\*\.bashStatus | numeric | 
action\_result\.data\.\*\.biosVersion | string | 
action\_result\.data\.\*\.bwf | numeric | 
action\_result\.data\.\*\.cidsBrowserFfOnOff | numeric | 
action\_result\.data\.\*\.cidsBrowserIeOnOff | numeric | 
action\_result\.data\.\*\.cidsDefsetVersion | string | 
action\_result\.data\.\*\.cidsDrvMulfCode | numeric | 
action\_result\.data\.\*\.cidsDrvOnOff | numeric | 
action\_result\.data\.\*\.cidsEngineVersion | string |  `ip` 
action\_result\.data\.\*\.cidsSilentMode | numeric | 
action\_result\.data\.\*\.computerDescription | string | 
action\_result\.data\.\*\.computerName | string |  `host name` 
action\_result\.data\.\*\.computerTimeStamp | numeric | 
action\_result\.data\.\*\.computerUsn | numeric | 
action\_result\.data\.\*\.contentUpdate | numeric | 
action\_result\.data\.\*\.creationTime | numeric | 
action\_result\.data\.\*\.currentClientId | string |  `md5` 
action\_result\.data\.\*\.daOnOff | numeric | 
action\_result\.data\.\*\.deleted | numeric | 
action\_result\.data\.\*\.department | string | 
action\_result\.data\.\*\.deploymentMessage | string | 
action\_result\.data\.\*\.deploymentPreVersion | string | 
action\_result\.data\.\*\.deploymentRunningVersion | string | 
action\_result\.data\.\*\.deploymentStatus | string | 
action\_result\.data\.\*\.deploymentTargetVersion | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.dhcpServer | string |  `ip` 
action\_result\.data\.\*\.diskDrive | string |  `file path` 
action\_result\.data\.\*\.dnsServers | string |  `ip` 
action\_result\.data\.\*\.domainOrWorkgroup | string |  `domain` 
action\_result\.data\.\*\.edrStatus | numeric | 
action\_result\.data\.\*\.elamOnOff | numeric | 
action\_result\.data\.\*\.email | string |  `email` 
action\_result\.data\.\*\.employeeNumber | string | 
action\_result\.data\.\*\.employeeStatus | string | 
action\_result\.data\.\*\.encryptedDevicePassword | string | 
action\_result\.data\.\*\.fbwf | numeric | 
action\_result\.data\.\*\.firewallOnOff | numeric | 
action\_result\.data\.\*\.freeDisk | numeric | 
action\_result\.data\.\*\.freeMem | numeric | 
action\_result\.data\.\*\.fullName | string | 
action\_result\.data\.\*\.gateways | string |  `ip` 
action\_result\.data\.\*\.group\.domain\.id | string |  `md5` 
action\_result\.data\.\*\.group\.domain\.name | string |  `symantec admin domain` 
action\_result\.data\.\*\.group\.externalId | string | 
action\_result\.data\.\*\.group\.fullPathName | string | 
action\_result\.data\.\*\.group\.id | string |  `symantec group id` 
action\_result\.data\.\*\.group\.name | string | 
action\_result\.data\.\*\.group\.source | string | 
action\_result\.data\.\*\.groupUpdateProvider | boolean | 
action\_result\.data\.\*\.hardwareKey | string |  `md5` 
action\_result\.data\.\*\.homePhone | string | 
action\_result\.data\.\*\.hypervisorVendorId | string | 
action\_result\.data\.\*\.idsChecksum | string | 
action\_result\.data\.\*\.idsSerialNo | string | 
action\_result\.data\.\*\.idsVersion | string | 
action\_result\.data\.\*\.infected | numeric | 
action\_result\.data\.\*\.installType | string | 
action\_result\.data\.\*\.ipAddresses | string |  `ip` 
action\_result\.data\.\*\.isGrace | numeric | 
action\_result\.data\.\*\.isNpvdiClient | numeric | 
action\_result\.data\.\*\.jobTitle | string | 
action\_result\.data\.\*\.kernel | string | 
action\_result\.data\.\*\.lastConnectedIpAddr | string |  `ip` 
action\_result\.data\.\*\.lastDeploymentTime | numeric | 
action\_result\.data\.\*\.lastDownloadTime | numeric | 
action\_result\.data\.\*\.lastHeuristicThreatTime | numeric | 
action\_result\.data\.\*\.lastScanTime | numeric | 
action\_result\.data\.\*\.lastServerId | string |  `md5` 
action\_result\.data\.\*\.lastServerName | string | 
action\_result\.data\.\*\.lastSiteId | string |  `md5` 
action\_result\.data\.\*\.lastSiteName | string | 
action\_result\.data\.\*\.lastUpdateTime | numeric | 
action\_result\.data\.\*\.lastVirusTime | numeric | 
action\_result\.data\.\*\.licenseExpiry | numeric | 
action\_result\.data\.\*\.licenseId | string | 
action\_result\.data\.\*\.licenseStatus | numeric | 
action\_result\.data\.\*\.logicalCpus | numeric | 
action\_result\.data\.\*\.loginDomain | string |  `domain` 
action\_result\.data\.\*\.logonUserName | string |  `user name` 
action\_result\.data\.\*\.macAddresses | string |  `mac address` 
action\_result\.data\.\*\.majorVersion | numeric | 
action\_result\.data\.\*\.memory | numeric | 
action\_result\.data\.\*\.minorVersion | numeric | 
action\_result\.data\.\*\.mobilePhone | string | 
action\_result\.data\.\*\.officePhone | string | 
action\_result\.data\.\*\.onlineStatus | numeric | 
action\_result\.data\.\*\.operatingSystem | string | 
action\_result\.data\.\*\.osBitness | string | 
action\_result\.data\.\*\.osElamStatus | numeric | 
action\_result\.data\.\*\.osFlavorNumber | numeric | 
action\_result\.data\.\*\.osFunction | string | 
action\_result\.data\.\*\.osLanguage | string | 
action\_result\.data\.\*\.osMajor | numeric | 
action\_result\.data\.\*\.osMinor | numeric | 
action\_result\.data\.\*\.osName | string | 
action\_result\.data\.\*\.osServicePack | string | 
action\_result\.data\.\*\.osVersion | string | 
action\_result\.data\.\*\.osbitness | string | 
action\_result\.data\.\*\.osflavorNumber | numeric | 
action\_result\.data\.\*\.osfunction | string | 
action\_result\.data\.\*\.oslanguage | string | 
action\_result\.data\.\*\.osmajor | numeric | 
action\_result\.data\.\*\.osminor | numeric | 
action\_result\.data\.\*\.osname | string | 
action\_result\.data\.\*\.osservicePack | string | 
action\_result\.data\.\*\.osversion | string | 
action\_result\.data\.\*\.patternIdx | string |  `md5` 
action\_result\.data\.\*\.pepOnOff | numeric | 
action\_result\.data\.\*\.physicalCpus | numeric | 
action\_result\.data\.\*\.processorClock | numeric | 
action\_result\.data\.\*\.processorType | string | 
action\_result\.data\.\*\.profileChecksum | string | 
action\_result\.data\.\*\.profileSerialNo | string | 
action\_result\.data\.\*\.profileVersion | string | 
action\_result\.data\.\*\.ptpOnOff | numeric | 
action\_result\.data\.\*\.publicKey | string | 
action\_result\.data\.\*\.quarantineDesc | string | 
action\_result\.data\.\*\.rebootReason | string | 
action\_result\.data\.\*\.rebootRequired | numeric | 
action\_result\.data\.\*\.securityVirtualAppliance | string | 
action\_result\.data\.\*\.serialNumber | string | 
action\_result\.data\.\*\.snacLicenseId | string | 
action\_result\.data\.\*\.subnetMasks | string | 
action\_result\.data\.\*\.svaId | string | 
action\_result\.data\.\*\.tamperOnOff | numeric | 
action\_result\.data\.\*\.timeZone | numeric | 
action\_result\.data\.\*\.tmpDevice | string | 
action\_result\.data\.\*\.totalDiskSpace | numeric | 
action\_result\.data\.\*\.tpmDevice | string | 
action\_result\.data\.\*\.uniqueId | string |  `symantec device id` 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.uwf | numeric | 
action\_result\.data\.\*\.virtualizationPlatform | string | 
action\_result\.data\.\*\.vsicStatus | numeric | 
action\_result\.data\.\*\.winServers | string |  `ip` 
action\_result\.data\.\*\.worstInfectionIdx | string | 
action\_result\.data\.\*\.writeFiltersStatus | string | 
action\_result\.summary\.system\_found | boolean | 
action\_result\.summary\.total\_endpoints | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get system info'
Gets the information about the computers in a specified domain

Type: **investigate**  
Read only: **True**

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**hostname** |  required  | Hostname of the device to get system info | string |  `host name` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.hostname | string |  `host name` 
action\_result\.data\.\*\.agentId | string | 
action\_result\.data\.\*\.agentTimeStamp | numeric | 
action\_result\.data\.\*\.agentType | string | 
action\_result\.data\.\*\.agentUsn | numeric | 
action\_result\.data\.\*\.agentVersion | string | 
action\_result\.data\.\*\.apOnOff | numeric | 
action\_result\.data\.\*\.atpDeviceId | string | 
action\_result\.data\.\*\.atpServer | string | 
action\_result\.data\.\*\.attributeExtension | string | 
action\_result\.data\.\*\.avEngineOnOff | numeric | 
action\_result\.data\.\*\.bashStatus | numeric | 
action\_result\.data\.\*\.biosVersion | string | 
action\_result\.data\.\*\.bwf | numeric | 
action\_result\.data\.\*\.cidsBrowserFfOnOff | numeric | 
action\_result\.data\.\*\.cidsBrowserIeOnOff | numeric | 
action\_result\.data\.\*\.cidsDefsetVersion | string | 
action\_result\.data\.\*\.cidsDrvMulfCode | numeric | 
action\_result\.data\.\*\.cidsDrvOnOff | numeric | 
action\_result\.data\.\*\.cidsEngineVersion | string | 
action\_result\.data\.\*\.cidsSilentMode | numeric | 
action\_result\.data\.\*\.computerDescription | string | 
action\_result\.data\.\*\.computerName | string |  `host name` 
action\_result\.data\.\*\.computerTimeStamp | numeric | 
action\_result\.data\.\*\.computerUsn | numeric | 
action\_result\.data\.\*\.contentUpdate | numeric | 
action\_result\.data\.\*\.creationTime | numeric | 
action\_result\.data\.\*\.currentClientId | string | 
action\_result\.data\.\*\.daOnOff | numeric | 
action\_result\.data\.\*\.deleted | numeric | 
action\_result\.data\.\*\.department | string | 
action\_result\.data\.\*\.deploymentMessage | string | 
action\_result\.data\.\*\.deploymentPreVersion | string | 
action\_result\.data\.\*\.deploymentRunningVersion | string | 
action\_result\.data\.\*\.deploymentStatus | string | 
action\_result\.data\.\*\.deploymentTargetVersion | string | 
action\_result\.data\.\*\.description | string | 
action\_result\.data\.\*\.dhcpServer | string |  `ip` 
action\_result\.data\.\*\.diskDrive | string |  `file path` 
action\_result\.data\.\*\.dnsServers | string |  `ip` 
action\_result\.data\.\*\.domainOrWorkgroup | string |  `domain` 
action\_result\.data\.\*\.edrStatus | numeric | 
action\_result\.data\.\*\.elamOnOff | numeric | 
action\_result\.data\.\*\.email | string |  `email` 
action\_result\.data\.\*\.employeeNumber | string | 
action\_result\.data\.\*\.employeeStatus | string | 
action\_result\.data\.\*\.encryptedDevicePassword | string | 
action\_result\.data\.\*\.fbwf | numeric | 
action\_result\.data\.\*\.firewallOnOff | numeric | 
action\_result\.data\.\*\.freeDisk | numeric | 
action\_result\.data\.\*\.freeMem | numeric | 
action\_result\.data\.\*\.fullName | string | 
action\_result\.data\.\*\.gateways | string |  `ip` 
action\_result\.data\.\*\.group\.domain\.id | string |  `md5` 
action\_result\.data\.\*\.group\.domain\.name | string |  `symantec admin domain` 
action\_result\.data\.\*\.group\.externalId | string | 
action\_result\.data\.\*\.group\.fullPathName | string | 
action\_result\.data\.\*\.group\.id | string |  `symantec group id` 
action\_result\.data\.\*\.group\.name | string | 
action\_result\.data\.\*\.group\.source | string | 
action\_result\.data\.\*\.groupUpdateProvider | boolean | 
action\_result\.data\.\*\.hardwareKey | string |  `md5` 
action\_result\.data\.\*\.homePhone | string | 
action\_result\.data\.\*\.hypervisorVendorId | string | 
action\_result\.data\.\*\.idsChecksum | string | 
action\_result\.data\.\*\.idsSerialNo | string | 
action\_result\.data\.\*\.idsVersion | string | 
action\_result\.data\.\*\.infected | numeric | 
action\_result\.data\.\*\.installType | string | 
action\_result\.data\.\*\.ipAddresses | string |  `ip` 
action\_result\.data\.\*\.isGrace | numeric | 
action\_result\.data\.\*\.isNpvdiClient | numeric | 
action\_result\.data\.\*\.jobTitle | string | 
action\_result\.data\.\*\.kernel | string | 
action\_result\.data\.\*\.lastConnectedIpAddr | string |  `ip` 
action\_result\.data\.\*\.lastDeploymentTime | numeric | 
action\_result\.data\.\*\.lastDownloadTime | numeric | 
action\_result\.data\.\*\.lastHeuristicThreatTime | numeric | 
action\_result\.data\.\*\.lastScanTime | numeric | 
action\_result\.data\.\*\.lastServerId | string | 
action\_result\.data\.\*\.lastServerName | string | 
action\_result\.data\.\*\.lastSiteId | string | 
action\_result\.data\.\*\.lastSiteName | string | 
action\_result\.data\.\*\.lastUpdateTime | numeric | 
action\_result\.data\.\*\.lastVirusTime | numeric | 
action\_result\.data\.\*\.licenseExpiry | numeric | 
action\_result\.data\.\*\.licenseId | string | 
action\_result\.data\.\*\.licenseStatus | numeric | 
action\_result\.data\.\*\.logicalCpus | numeric | 
action\_result\.data\.\*\.loginDomain | string |  `domain` 
action\_result\.data\.\*\.logonUserName | string |  `user name` 
action\_result\.data\.\*\.macAddresses | string |  `mac address` 
action\_result\.data\.\*\.majorVersion | numeric | 
action\_result\.data\.\*\.memory | numeric | 
action\_result\.data\.\*\.minorVersion | numeric | 
action\_result\.data\.\*\.mobilePhone | string | 
action\_result\.data\.\*\.officePhone | string | 
action\_result\.data\.\*\.onlineStatus | numeric | 
action\_result\.data\.\*\.operatingSystem | string | 
action\_result\.data\.\*\.osBitness | string | 
action\_result\.data\.\*\.osElamStatus | numeric | 
action\_result\.data\.\*\.osFlavorNumber | numeric | 
action\_result\.data\.\*\.osFunction | string | 
action\_result\.data\.\*\.osLanguage | string | 
action\_result\.data\.\*\.osMajor | numeric | 
action\_result\.data\.\*\.osMinor | numeric | 
action\_result\.data\.\*\.osName | string | 
action\_result\.data\.\*\.osServicePack | string | 
action\_result\.data\.\*\.osVersion | string | 
action\_result\.data\.\*\.osbitness | string | 
action\_result\.data\.\*\.osflavorNumber | numeric | 
action\_result\.data\.\*\.osfunction | string | 
action\_result\.data\.\*\.oslanguage | string | 
action\_result\.data\.\*\.osmajor | numeric | 
action\_result\.data\.\*\.osminor | numeric | 
action\_result\.data\.\*\.osname | string | 
action\_result\.data\.\*\.osservicePack | string | 
action\_result\.data\.\*\.osversion | string | 
action\_result\.data\.\*\.patternIdx | string |  `md5` 
action\_result\.data\.\*\.pepOnOff | numeric | 
action\_result\.data\.\*\.physicalCpus | numeric | 
action\_result\.data\.\*\.processorClock | numeric | 
action\_result\.data\.\*\.processorType | string | 
action\_result\.data\.\*\.profileChecksum | string | 
action\_result\.data\.\*\.profileSerialNo | string | 
action\_result\.data\.\*\.profileVersion | string | 
action\_result\.data\.\*\.ptpOnOff | numeric | 
action\_result\.data\.\*\.publicKey | string | 
action\_result\.data\.\*\.quarantineDesc | string | 
action\_result\.data\.\*\.rebootReason | string | 
action\_result\.data\.\*\.rebootRequired | numeric | 
action\_result\.data\.\*\.securityVirtualAppliance | string | 
action\_result\.data\.\*\.serialNumber | string | 
action\_result\.data\.\*\.snacLicenseId | string | 
action\_result\.data\.\*\.subnetMasks | string | 
action\_result\.data\.\*\.svaId | string | 
action\_result\.data\.\*\.tamperOnOff | numeric | 
action\_result\.data\.\*\.timeZone | numeric | 
action\_result\.data\.\*\.tmpDevice | string | 
action\_result\.data\.\*\.totalDiskSpace | numeric | 
action\_result\.data\.\*\.tpmDevice | string | 
action\_result\.data\.\*\.uniqueId | string |  `symantec device id` 
action\_result\.data\.\*\.uuid | string | 
action\_result\.data\.\*\.uwf | numeric | 
action\_result\.data\.\*\.virtualizationPlatform | string | 
action\_result\.data\.\*\.vsicStatus | numeric | 
action\_result\.data\.\*\.winServers | string |  `ip` 
action\_result\.data\.\*\.worstInfectionIdx | string | 
action\_result\.data\.\*\.writeFiltersStatus | string | 
action\_result\.summary\.system\_found | boolean | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'get status'
Get command status report

Type: **investigate**  
Read only: **True**

This action provides detailed information about the execution of a specified command on a specified client\. Status of the command can be evaluated based on three output parameters <b>stateId</b>, <b>subStateId</b> and <b>subStateDesc</b>\.<br><b>stateId</b> does not necessarily return one of the below state values\. Possible values are\:<ul><li>0 = INITIAL</li><li>1 = RECEIVED</li><li>2 = IN\_PROGRESS</li><li>3 = COMPLETED</li><li>4 = REJECTED</li><li>5 = CANCELED</li><li>6 = ERROR</li></ul><br><b>subStateId</b> does not necessarily return one of the below state values\. Possible values are\:<ul><li>\-1 = Unknown</li><li>0 = Success</li><li>1 = Client did not execute the command</li><li>2 = Client did not report any status</li><li>3 = Command was a duplicate and not executed</li><li>4 = Spooled command could not restart</li><li>5 = Restart command not allowed from the console</li><li>6 = Unexpected error</li><li>100 = Success</li><li>101 = Security risk found</li><li>102 = Scan was suspended</li><li>103 = Scan was aborted</li><li>105 = Scan did not return status</li><li>106 = Scan failed to start</li><li>110 = Auto\-Protect cannot be turned on</li><li>120 = LiveUpdate download is in progress</li><li>121 = LiveUpdate download failed</li><li>131 = Quarantine delete failed</li><li>132 = Quarantine delete partial success</li><li>141 = Evidence of Compromise scan failed</li><li>142 = Evidence of Compromise scan failed\: XML invalid or could not be parsed</li><li>146 = Evidence of Compromise file validation failed on the server</li></ul><br><b>subStateDesc</b> does not necessarily return one of the below state values\. Possible values are\:<ul><li>\-1 = Unknown</li><li>0 = Success</li><li>1 = Client did not execute the command</li></ul>\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  required  | Command ID | string |  `symantec command id` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `symantec command id` 
action\_result\.data\.\*\.beginTime | string | 
action\_result\.data\.\*\.binaryFileId | string | 
action\_result\.data\.\*\.computerId | string |  `symantec device id` 
action\_result\.data\.\*\.computerIp | string |  `ip` 
action\_result\.data\.\*\.computerName | string |  `host name` 
action\_result\.data\.\*\.currentLoginUserName | string |  `user name` 
action\_result\.data\.\*\.domainName | string |  `symantec admin domain` 
action\_result\.data\.\*\.hardwareKey | string |  `md5` 
action\_result\.data\.\*\.lastUpdateTime | string | 
action\_result\.data\.\*\.resultInXML | string | 
action\_result\.data\.\*\.stateId | numeric | 
action\_result\.data\.\*\.subStateDesc | string | 
action\_result\.data\.\*\.subStateId | numeric | 
action\_result\.summary\.command\_state | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unquarantine device'
Unquarantine the endpoint

Type: **correct**  
Read only: **False**

Either <b>id</b> or <b>ip\_hostname</b> of an endpoint needs to be specified to unquarantine an endpoint\. If <b>id</b> is specified, <b>ip\_hostname</b> is ignored\.<br>The action <i>sends</i> the unquarantine command to the SEP Manager and returns with the command id\. The command takes some time \(usually under a minute\) to complete\. The <b>get status</b> action can be used to get the status of the command\. The action will start the unquarantine process and poll for the amount of seconds passed in the <b>timeout</b> parameter to get the latest status of the action\. If any value of the computerID, IP or hostname is given wrong in the comma separated string in the respective parameters, the action will fail\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  optional  | Comma\(,\) separated Computer IDs of the endpoints to unquarantine | string |  `symantec device id` 
**ip\_hostname** |  optional  | Comma\(,\) separated Hostname/IP of the endpoints to unquarantine | string |  `ip`  `host name` 
**timeout** |  optional  | Timeout \(Default\: 30 seconds\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `symantec device id` 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.timeout | numeric | 
action\_result\.data\.\*\.beginTime | string | 
action\_result\.data\.\*\.binaryFileId | string | 
action\_result\.data\.\*\.computerId | string |  `md5` 
action\_result\.data\.\*\.computerIp | string |  `ip` 
action\_result\.data\.\*\.computerName | string |  `host name` 
action\_result\.data\.\*\.currentLoginUserName | string |  `user name` 
action\_result\.data\.\*\.domainName | string |  `domain` 
action\_result\.data\.\*\.hardwareKey | string |  `md5` 
action\_result\.data\.\*\.lastUpdateTime | string | 
action\_result\.data\.\*\.resultInXML | string | 
action\_result\.data\.\*\.stateId | numeric | 
action\_result\.data\.\*\.subStateDesc | string | 
action\_result\.data\.\*\.subStateId | numeric | 
action\_result\.summary\.command\_id | string |  `symantec command id` 
action\_result\.summary\.state\_id\_status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'quarantine device'
Quarantine the endpoint

Type: **contain**  
Read only: **False**

Either <b>id</b> or <b>ip\_hostname</b> of an endpoint needs to be specified to quarantine an endpoint\. If <b>id</b> is specified, <b>ip\_hostname</b> is ignored\.<br>The action <i>sends</i> the quarantine command to the SEP Manager and returns with the command id\. The command takes some time \(usually under a minute\) to complete\. The <b>get status</b> action can be used to get the status of the command\. The action will start the quarantine process and poll for the amount of seconds passed in the <b>timeout</b> parameter to get the latest status of the action\. If any value of the computerID, IP or hostname is given wrong in the comma separated string in the respective parameters, the action will fail\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  optional  | Comma\(,\) separated Computer IDs of the endpoints to quarantine | string |  `symantec device id` 
**ip\_hostname** |  optional  | Comma\(,\) separated Hostname/IP of the endpoints to quarantine | string |  `ip`  `host name` 
**timeout** |  optional  | Timeout \(Default\: 30 secs\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `symantec device id` 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.timeout | numeric | 
action\_result\.data\.\*\.beginTime | string | 
action\_result\.data\.\*\.binaryFileId | string | 
action\_result\.data\.\*\.computerId | string |  `md5` 
action\_result\.data\.\*\.computerIp | string |  `ip` 
action\_result\.data\.\*\.computerName | string |  `host name` 
action\_result\.data\.\*\.currentLoginUserName | string |  `user name` 
action\_result\.data\.\*\.domainName | string |  `domain` 
action\_result\.data\.\*\.hardwareKey | string |  `md5` 
action\_result\.data\.\*\.lastUpdateTime | string | 
action\_result\.data\.\*\.resultInXML | string | 
action\_result\.data\.\*\.stateId | numeric | 
action\_result\.data\.\*\.subStateDesc | string | 
action\_result\.data\.\*\.subStateId | numeric | 
action\_result\.summary\.command\_id | string |  `symantec command id` 
action\_result\.summary\.state\_id\_status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'unblock hash'
Unblock hashes on endpoints

Type: **correct**  
Read only: **False**

This action removes all the MD5 hashes provided in <b>hash</b> from a fingerprint file\. If all hashes from the fingerprint file are removed, then the fingerprint file will be deleted from SEP\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group\_id** |  required  | Group ID | string |  `symantec group id` 
**hash** |  required  | Comma\(,\) separated MD5 hash value of files to unblock | string |  `md5` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.group\_id | string |  `symantec group id` 
action\_result\.parameter\.hash | string |  `md5` 
action\_result\.data\.\*\.fingerprint\_file\_info\.data | string |  `md5` 
action\_result\.data\.\*\.fingerprint\_file\_info\.description | string | 
action\_result\.data\.\*\.fingerprint\_file\_info\.domainId | string |  `md5` 
action\_result\.data\.\*\.fingerprint\_file\_info\.groupIds | string |  `symantec group id` 
action\_result\.data\.\*\.fingerprint\_file\_info\.hashType | string | 
action\_result\.data\.\*\.fingerprint\_file\_info\.id | string | 
action\_result\.data\.\*\.fingerprint\_file\_info\.name | string | 
action\_result\.data\.\*\.fingerprint\_file\_info\.source | string | 
action\_result\.data\.\*\.hash\_info\.\*\.context | string | 
action\_result\.data\.\*\.hash\_info\.\*\.data | string | 
action\_result\.data\.\*\.hash\_info\.\*\.extra\_data | string | 
action\_result\.data\.\*\.hash\_info\.\*\.message | string | 
action\_result\.data\.\*\.hash\_info\.\*\.parameter\.hash | string |  `md5` 
action\_result\.data\.\*\.hash\_info\.\*\.status | string | 
action\_result\.data\.\*\.hash\_info\.\*\.summary | string | 
action\_result\.summary\.hashes\_already\_unblocked | numeric | 
action\_result\.summary\.hashes\_unblocked | numeric | 
action\_result\.summary\.invalid\_hashes | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'block hash'
Block hashes on endpoints

Type: **contain**  
Read only: **False**

This action creates a fingerprint file on SEP manager for a given <b>group\_id</b> and adds all the MD5 hashes provided in <b>hash</b> to the file\. This file will be connected in blacklist mode to the System Lockdown setting of the group referred by <b>group\_id</b>\. Hashes of files having extensions either \.exe, \.com, \.dll or \.ocx will be used to block an application from launching on endpoints\.<br>In order to add an application to a group in blocked mode, the group must not inherit policies and settings of its parent group\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**group\_id** |  required  | Group ID | string |  `symantec group id` 
**hash** |  required  | Comma\(,\) separated MD5 hash value of files to block | string |  `md5` 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.group\_id | string |  `symantec group id` 
action\_result\.parameter\.hash | string |  `md5` 
action\_result\.data\.\*\.fingerprint\_file\_info\.description | string | 
action\_result\.data\.\*\.fingerprint\_file\_info\.domainId | string |  `md5` 
action\_result\.data\.\*\.fingerprint\_file\_info\.hashType | string | 
action\_result\.data\.\*\.fingerprint\_file\_info\.id | string |  `md5` 
action\_result\.data\.\*\.fingerprint\_file\_info\.name | string | 
action\_result\.data\.\*\.hash\_info\.\*\.context | string | 
action\_result\.data\.\*\.hash\_info\.\*\.data | string | 
action\_result\.data\.\*\.hash\_info\.\*\.extra\_data | string | 
action\_result\.data\.\*\.hash\_info\.\*\.message | string | 
action\_result\.data\.\*\.hash\_info\.\*\.parameter\.hash | string |  `md5` 
action\_result\.data\.\*\.hash\_info\.\*\.status | string | 
action\_result\.data\.\*\.hash\_info\.\*\.summary | string | 
action\_result\.summary\.hashes\_already\_blocked | numeric | 
action\_result\.summary\.hashes\_already\_unblocked | numeric | 
action\_result\.summary\.hashes\_blocked | numeric | 
action\_result\.summary\.invalid\_hashes | numeric | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'scan endpoint'
Scan an endpoint

Type: **investigate**  
Read only: **True**

Either <b>id</b> or <b>ip\_hostname</b> of an endpoint needs to be specified to scan an endpoint\. If <b>id</b> is specified, <b>ip\_hostname</b> is ignored\.<br>The <b>type</b> parameter can be one of the following values\:<ul><li>QUICK\_SCAN</li><li>FULL\_SCAN</li></ul>The action will start the scan and poll for the amount of seconds passed in the <b>timeout</b> parameter to get the latest status of the poll\. If any value of the computerID, IP or hostname is given wrong in the comma separated string in the respective parameters, the action will fail\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**id** |  optional  | Comma\(,\) separated Computer IDs of the endpoints to scan | string |  `symantec device id` 
**ip\_hostname** |  optional  | Comma\(,\) separated Hostname/IP of the endpoints to scan | string |  `ip`  `host name` 
**type** |  optional  | Scan Type \(Default\: QUICK\_SCAN\) | string |  `symantec scan type` 
**timeout** |  optional  | Timeout \(Default\: 30 seconds\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.id | string |  `symantec device id` 
action\_result\.parameter\.ip\_hostname | string |  `ip`  `host name` 
action\_result\.parameter\.timeout | numeric | 
action\_result\.parameter\.type | string |  `symantec scan type` 
action\_result\.data\.\*\.EOC\.\@creator | string | 
action\_result\.data\.\*\.EOC\.\@id | string | 
action\_result\.data\.\*\.EOC\.\@version | string | 
action\_result\.data\.\*\.EOC\.Activity | string | 
action\_result\.data\.\*\.EOC\.DataSource\.\@id | string | 
action\_result\.data\.\*\.EOC\.DataSource\.\@name | string | 
action\_result\.data\.\*\.EOC\.DataSource\.\@version | string | 
action\_result\.data\.\*\.EOC\.ScanType | string |  `symantec scan type` 
action\_result\.data\.\*\.EOC\.Threat\.\@category | string | 
action\_result\.data\.\*\.EOC\.Threat\.\@severity | string | 
action\_result\.data\.\*\.EOC\.Threat\.\@time | string | 
action\_result\.data\.\*\.EOC\.Threat\.\@type | string | 
action\_result\.data\.\*\.EOC\.Threat\.Application | string | 
action\_result\.data\.\*\.EOC\.Threat\.Attacker | string | 
action\_result\.data\.\*\.EOC\.Threat\.Description | string | 
action\_result\.data\.\*\.EOC\.Threat\.URL | string | 
action\_result\.data\.\*\.EOC\.Threat\.User | string | 
action\_result\.data\.\*\.EOC\.Threat\.proxy\.\@ip | string | 
action\_result\.data\.\*\.beginTime | string | 
action\_result\.data\.\*\.binaryFileId | string | 
action\_result\.data\.\*\.computerId | string |  `md5` 
action\_result\.data\.\*\.computerIp | string |  `ip` 
action\_result\.data\.\*\.computerName | string |  `host name` 
action\_result\.data\.\*\.currentLoginUserName | string |  `user name` 
action\_result\.data\.\*\.domainName | string |  `domain` 
action\_result\.data\.\*\.hardwareKey | string |  `md5` 
action\_result\.data\.\*\.lastUpdateTime | string | 
action\_result\.data\.\*\.stateId | numeric | 
action\_result\.data\.\*\.subStateDesc | string | 
action\_result\.data\.\*\.subStateId | numeric | 
action\_result\.summary\.command\_id | string |  `symantec command id` 
action\_result\.summary\.state\_id\_status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric |   

## action: 'full scan'
Scan a computer

Type: **investigate**  
Read only: **True**

Either <b>computer\_id</b> or <b>group\_id</b> needs to be specified to perform fullscan/activescan\. If both <b>computer\_id</b> and <b>group\_id</b> are specified, selected scan will start for both values\.<br>The <b>type</b> parameter can be one of the following values\:<ul><li>activescan</li><li>fullscan</li></ul>The action will start the scan and poll for the amount of seconds passed in the <b>timeout</b> parameter to get the latest status of the poll\. If any value of the computerID or groupID is given wrong in the comma separated string in the respective parameters, the action will fail\.

#### Action Parameters
PARAMETER | REQUIRED | DESCRIPTION | TYPE | CONTAINS
--------- | -------- | ----------- | ---- | --------
**computer\_id** |  optional  | Comma\(,\) separated computer IDs to scan | string |  `symantec device id` 
**group\_id** |  optional  | Comma\(,\) separated group IDs to scan | string |  `symantec group id` 
**type** |  optional  | Scan Type \(Default\: fullscan\) | string |  `symantec fullscan type` 
**timeout** |  optional  | Timeout \(Default\: 30 seconds\) | numeric | 

#### Action Output
DATA PATH | TYPE | CONTAINS
--------- | ---- | --------
action\_result\.status | string | 
action\_result\.parameter\.computer\_id | string |  `symantec device id` 
action\_result\.parameter\.group\_id | string |  `symantec group id` 
action\_result\.parameter\.timeout | numeric | 
action\_result\.parameter\.type | string |  `symantec fullscan type` 
action\_result\.data\.\*\.beginTime | string | 
action\_result\.data\.\*\.binaryFileId | string | 
action\_result\.data\.\*\.computerId | string |  `symantec device id` 
action\_result\.data\.\*\.computerIp | string | 
action\_result\.data\.\*\.computerName | string | 
action\_result\.data\.\*\.currentLoginUserName | string | 
action\_result\.data\.\*\.domainName | string | 
action\_result\.data\.\*\.hardwareKey | string | 
action\_result\.data\.\*\.lastUpdateTime | string | 
action\_result\.data\.\*\.resultInXML | string | 
action\_result\.data\.\*\.stateId | numeric | 
action\_result\.data\.\*\.subStateDesc | string | 
action\_result\.data\.\*\.subStateId | numeric | 
action\_result\.summary\.computer\_command\_id | string |  `symantec command id` 
action\_result\.summary\.group\_command\_id | string |  `symantec command id` 
action\_result\.summary\.state\_computer\_id\_status | string | 
action\_result\.summary\.state\_group\_id\_status | string | 
action\_result\.message | string | 
summary\.total\_objects | numeric | 
summary\.total\_objects\_successful | numeric | 