# Set-ReceiveConnectorIpAddress.ps1

Add or remove remote IP address ranges (es) to an existing receive connector on all Exchange 2013+ Servers

## Description

This script adds or removes IP addresses or IP address ranges to/from existing Receive Connectors.
The input file can contain more than one IP address (range), one entry per line.
The IP address parameter can be used to add a single IP address.
The script creates a new sub directory beneath the current location of the script.
The script utilizes the directory as a log directory to store the current remote IP address ranges prior modification.
A log is written to the \log subfolder utilitzing the GlobalFunctions Logger object.

This script is a replacement for [https://github.com/Apoc70/Add-ReceiveConnectorIpAddress](https://github.com/Apoc70/Add-ReceiveConnectorIpAddress)

## Requirements

- Registered GlobalModules PowerShell module, [http://scripts.granikos.eu](http://scripts.granikos.eu)
- Windows Server 2016, Windows Server 2012 R2, Windows Server 2008 R2 SP1
- Exchange ManagementShell 2013+
- Optionally, a txt file containing new remote IP address ranges, one per line

Example:
192.168.1.1
192.168.2.10-192.168.2.20
192.168.3.0/24

## Parameters

### ConnectorName

Name of the receive connector the new IP addresses should be added to

### FileName

Name of the input file name containing IP addresses, file must be located in the same directory as the PowerShell script

### IpAddress

Single IP address for being added/removed to/from a receive connector

### Action

Add - add remote IP address ranges
Remove - remove remote IP address ranges

### ViewEntireForest

View entire Active Directory forest (default FALSE)

### Comment

Additonal comment on why an IP address is added or removed

## Examples

``` PowerShell
.\Set-ReceiveConnectorIpAddress.ps1 -ConnectorName RelayConnector -FileName D:\Scripts\ip.txt -Action Add
```

Add all IP addresses stored in D:\Scripts\ip.txt to a receive connector named RelayConnector

``` PowerShell 
.\Set-ReceiveConnectorIpAddress.ps1 -ConnectorName MyConnector -IpAddress 10.10.10.1 -Action Remove -ViewEntireForest $true
```

Remove IP address 10.10.10.1 from a receive connector nameds MyConnector from all Exchange Servers in the forest

``` PowerShell
.\Set-ReceiveConnectorIpAddress.ps1 -ConnectorName MyConnector -IpAddress 10.10.10.1 -Action Remove -ViewEntireForest $true -Comment 'Personal request of upper management'
```

Remove IP address 10.10.10.1 from a receive connector nameds MyConnector from all Exchange Servers in the forest with comment 'Personal request of upper management'

## Note

THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE
RISK OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER.

## TechNet Gallery

Download and vote at TechNet Gallery

* [TechNet Link] (https://gallery.technet.microsoft.com/Script-to-remove-unwanted-9d119c6b)

## Credits

Written by: Thomas Stensitzki

Stay connected:

* My Blog: [http://justcantgetenough.granikos.eu](http://justcantgetenough.granikos.eu)
* Twitter: [https://twitter.com/stensitzki](https://twitter.com/stensitzki)
* LinkedIn: [http://de.linkedin.com/in/thomasstensitzki](http://de.linkedin.com/in/thomasstensitzki)
* Github: [https://github.com/Apoc70](https://github.com/Apoc70)

For more Office 365, Cloud Security, and Exchange Server stuff checkout services provided by Granikos

* Blog: [http://blog.granikos.eu](http://blog.granikos.eu)
* Website: [https://www.granikos.eu/en/](https://www.granikos.eu/en/)
* Twitter: [https://twitter.com/granikos_de](https://twitter.com/granikos_de)