<# 
  .SYNOPSIS 
  Add or remove remote IP address ranges (es) to an existing receive connector on all Exchange 2013+ Servers

  Thomas Stensitzki 

  THIS CODE IS MADE AVAILABLE AS IS, WITHOUT WARRANTY OF ANY KIND. THE ENTIRE  
  RISK OF THE USE OR THE RESULTS FROM THE USE OF THIS CODE REMAINS WITH THE USER. 

  Version 1.0, 2017-11-15

  Please send ideas, comments and suggestions to support@granikos.eu 

  .LINK 
  http://scripts.granikos.eu

  .DESCRIPTION 
  This script adds or removes IP addresses or IP address ranges to/from existing Receive Connectors.
  The input file can contain more than one IP address (range), on entry per line.
  The IP address parameter can be used to add a single IP address.
  The script creates a new sub directory beneath the current location of the script.
  The script utilizes the directory as a log directory to store the current remote IP address ranges prior modification.
  A log is written to the \log subfolder utilitzing the GlobalFunctions Logger object
 
  .NOTES 
  Requirements 
  - Registered GlobalModules PowerShell module, http://scripts.granikos.eu  
  - Windows Server 2016, Windows Server 2012 R2, Windows Server 2008 R2 SP1  
  - Exhange ManagementShell 2013+
  - Optionally, a txt file containing new remote IP address ranges, one per line
  Example:
  192.168.1.1
  192.168.2.10-192.168.2.20
  192.168.3.0/24
    
  Revision History 
  -------------------------------------------------------------------------------- 
  1.0 Initial community release 
  
  .PARAMETER ConnectorName  
  Name of the receive connector the new IP addresses should be added to  

  .PARAMETER FileName
  Name of the input file name containing IP addresses, file must be located in the same directory as the PowerShell script

  .PARAMETER IpAddress
  Single IP address for being added/removed to/from a receive connector

  .PARAMETER Action
  Add - add remote IP address ranges
  Remove - remove remote IP address ranges

  .PARAMETER ViewEntireForest
  View entire Active Directory forest (default FALSE)
    
  .EXAMPLE 
  .\Set-ReceiveConnectorIpAddress.ps1 -ConnectorName RelayConnector -FileName D:\Scripts\ip.txt -Action Add

  .EXAMPLE 
  .\Set-ReceiveConnectorIpAddress.ps1 -ConnectorName MyConnector -IpAddress 10.10.10.1 -Action Remove -ViewEntireForest $true

#> 
[cmdletbinding(DefaultParameterSetName='IP')]
param(
  [parameter(Mandatory,HelpMessage='Receive Connector Name',ParameterSetName='IP')]
  [parameter(Mandatory,HelpMessage='Receive Connector Name',ParameterSetName='F')]
  [string] $ConnectorName,
  [parameter(Mandatory,ParameterSetName='F')]
  [string] $FileName = '',
  [parameter(ParameterSetName='IP')]
  [ValidateScript({$_ -match [IPAddress]$_ })]  
  [string] $IpAddress = '',
  [parameter(Mandatory,HelpMessage='Action to add or remove a remote IP range is required',ParameterSetName='IP')]
  [ValidateSet('Add','Remove')]
  [parameter(Mandatory,HelpMessage='Action to add or remove a remote IP range is required',ParameterSetName='F')]
  [ValidateSet('Add','Remove')]
  [string] $Action,
  [parameter(ParameterSetName='IP')]
  [parameter(ParameterSetName='F')]
  [bool] $ViewEntireForest = $false
)

# 
$tmpFileFolderName = 'ReceiveConnectorIpAddresses'
$tmpFileLocation = ''

# Timestamp for use in filename, adjust formatting to your regional requirements
$timeStamp = Get-Date -Format "yyyy-MM-dd HHmmss"

# Implementation of global functions module
Import-Module -Name GlobalFunctions
$ScriptDir = Split-Path -Path $script:MyInvocation.MyCommand.Path
$ScriptName = $MyInvocation.MyCommand.Name
$logger = New-Logger -ScriptRoot $ScriptDir -ScriptName $ScriptName -LogFileRetention 14
$logger.Write('Script started')

function Test-LogPath {
  $script:tmpFileLocation = Join-Path -Path $PSScriptRoot -ChildPath $tmpFileFolderName

  if(-not (Test-Path -Path $script:tmpFileLocation)) {
    $logger.Write( 'New folder for storing IP Remote Ranges created' )
    $null = New-Item -ItemType Directory -Path $script:tmpFileLocation -Force
  }
}

function Test-ReceiveConnector {
  [CmdletBinding()]
  param(
    [string]$Server
  )

  Write-Verbose -Message ('Checking Server: {0}' -f $Server)

  $targetRC = $null

  try { 
    # Fetch receive connector from server
    $targetRC = Get-ReceiveConnector -Server $Server | Where-Object {$_.name -eq $ConnectorName} -ErrorAction SilentlyContinue
  }
  catch {
    $logger.Write( ('Error fetching connector {0} on server {1}' -f $ConnectorName, $Server) ) 
  }

  if($targetRC -ne $null) {

    $logger.Write( ('Connector {0} found on server {1}' -f $ConnectorName, $Server) )

    Write-Host "Checking ReceiveConnector on Server: $Server"
    
    # Save current RemoteIpRange before we change any IP address
    Export-ConnectorIpRanges -ReceiveConnector $targetRC
  
  }
}

function Export-ConnectorIpRanges {
  [CmdletBinding()]
  param (
    $ReceiveConnector
  )
  # Create a list of currently configured IP ranges 
  $tmpRemoteIpRanges =''

  foreach ( $remoteIpRange in ($ReceiveConnector).RemoteIPRanges ) {
    $tmpRemoteIpRanges += ("`r`n{0}" -f $remoteIpRange)			
  }

  Write-Verbose -Message $tmpFileLocation
    
  # Save current remote IP ranges for connector to disk
  $fileIpRanges = (('{0}\{1}-{2}-Export.txt' -f $tmpFileLocation, $ConnectorName, $timeStamp)).ToUpper()
  $logger.Write( ('Saving current IP ranges to: {0}' -f $fileIpRanges) )
  $tmpRemoteIpRanges | Out-File -FilePath $fileIpRanges -Force -Encoding UTF8

  # Fetch new IP ranges from disk
  $newIpRangesFileContent = ''

  if ($FileName -ne '') { 
    # we need to import IP ranges from a file

    if(Test-Path -Path $FileName) {
      $newIpRangesFileContent = Get-Content -Path $FileName
    }
  }
  elseif ($IpAddress -ne '') {
    # have a single IP address

    $newIpRangesFileContent = $IpAddress
  }

  # check IP ranges, if file exsists
  if($newIpRangesFileContent -ne '') {

    foreach ($newIpRange in $newIpRangesFileContent ){

      $logger.Write( ('Checking Remote IP range {0} in {1}' -f $newIpRange, $fileIpRanges) )

      # Check if new remote IP range already exists in configure remote IP range of connector
      $ipSearch = (Select-String -Pattern $newIpRange -Path $fileIpRanges )

      if ($ipSearch -ne $null ){
        # IP address exists
        switch ($Action) {
          'Add' {
            $logger.Write( ('{0} already exists in {1} and CANNOT be added' -f $newIpRange, $ConnectorName) )
          }
          'Remove' {
            $logger.Write( ('{0} exists in {1} and will be removed' -f $newIpRange, $ConnectorName) )
            $ReceiveConnector.RemoteIPRanges -= $newIpRange
          }
          default {}
        }
      }
      else {

        # Remote IP range does not exist 
        switch ($Action) {
          'Add' {
            $logger.Write( ('{0} does not exist in {1} and will be added' -f $newIpRange, $ConnectorName) )
            $ReceiveConnector.RemoteIPRanges += $newIpRange
          }
          'Remove' {
            $logger.Write( ('{0} does NOT exist in {1} and CANNOT be removed' -f $newIpRange, $ConnectorName) )
          }
          default {}
        }
      }
    }

    # save changes to receive connector
    Set-ReceiveConnector -Identity $ReceiveConnector.Identity -RemoteIPRanges $ReceiveConnector.RemoteIPRanges | Sort-Object -Unique

  } 
  else {
    $logger.Write( ('Empty file: {0}' -f $FileName) )
  }   
}

# MAIN -------------------------------------------------------

if($ViewEntireForest) {
    $logger.Write( ('Setting ADServerSettings -ViewEntireForest {0}' -f $true) )
    Set-ADServerSettings -ViewEntireForets $true
}

if($FileName -ne '') {
  if(-not (Test-Path -Path $FileName)) {
    $ErrorMessage = ('{0} does not exist!' -f $FileName)
    Write-Error -Message $ErrorMessage
    $logger.Write($ErrorMessage, 1)
    exit 99
  }
}

Test-LogPath

# Fetch all Exchange 2013+ Servers
$allExchangeServers = Get-ExchangeServer | Where-Object{($_.AdminDisplayVersion.Major -eq 15) -and ([string]$_.ServerRole).Contains("ClientAccess")} | Sort-Object

foreach($Server in $AllExchangeServers) {
    $logger.Write( ('Checking receive connector {0} on server {1}' -f $ConnectorName, $Server) )

    Test-ReceiveConnector -Server $Server
}
