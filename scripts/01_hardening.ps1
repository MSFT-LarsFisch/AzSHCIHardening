<#
  .SYNOPSIS
  Check your Azure Stack HCI Hardening.

  .DESCRIPTION
  The 01_hardening.ps1 script checks the registry for the current hardening.

  .PARAMETER CSVInputPath
  Specifies the path to the CSV-based input file
  
  .PARAMETER HardCheck
  Specifies if this script runs in check mode or in set mode, valid inputs are "check" or "insert"

  .PARAMETER OutputPath
  Specifies the name and path for the CSV-based output file. By default,
  00_getcurrentstate.ps1 generates a output file with the current state of hardening, and
  saves the output in the local directory.

  .INPUTS
  None. You cannot pipe objects to 00_getcurrentstate.ps1.

  .OUTPUTS
  00_getcurrentstate.ps1 generates in the current folder a dedicated logfile

  .EXAMPLE
  PS> .\00_getcurrentstate.ps1 -inputpath "C:\temp\Baseline_2210.csv"
#>
[CmdletBinding()]
param (
    [Parameter(Mandatory=$true)]
    [string]$CSVInputPath,
    [Parameter(Mandatory=$true)]
    [ValidateSet("check","insert")]
    [string]$HardCheck

)

function Log($text) {
    CreateFolder "$PSScriptRoot\Log"

    if ($null -eq $global:logFileTime) {
        $global:logFileTime = Get-Date -Format "yyyyMMdd_HHmm"
    }
    $logRunTime = Get-Date -Format "HH:mm:ss"
    "$logRunTime |          $text" | Out-File "$PSScriptRoot\Log\Log_$((Split-path $MyInvocation.ScriptName -Leaf).Replace('.ps1', ''))_$global:logFileTime.txt" -Append -Force
}

function LogError($text) {
    CreateFolder "$PSScriptRoot\Error"

    if ($null -eq $global:logFileTime) {
        $global:logFileTime = Get-Date -Format "yyyyMMdd_HHmm"
    }
    $logRunTime = Get-Date -Format "HH:mm:ss"
    "$logRunTime |          $text" | Out-File "$PSScriptRoot\Error\Error_$((Split-path $MyInvocation.ScriptName -Leaf).Replace('.ps1', ''))_$global:logFileTime.txt" -Append -Force
}
function CreateFolder($path) {
    if ((Test-Path $path) -eq $false) {
        New-Item -ItemType directory -Path $path | Out-Null
    }
}
function Get-RegKeyValue
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Regkey,
        [Parameter(Mandatory=$true)]
        [string]$RegKeyName,
        [Parameter(Mandatory=$true)]
        [string]$RegKeyValue
    )
    process {
        if (test-path $Regkey)
        {
            $tempRegKey = Get-Item -LiteralPath $Regkey
            if ($null -ne $tempRegKey.GetValue($RegKeyName, $null)) {
                if ($PassThru) {
                    Get-ItemProperty $Regkey $RegKeyName
                    $tempRegKeyValue = Get-ItemPropertyValue $Regkey $RegKeyName
                } else {
                    $tempRegKeyValue = Get-ItemPropertyValue $Regkey $RegKeyName
                    $tempRegKeyValueKind = (Get-Item $Regkey).GetValueKind($RegKeyName)
                    Log("$RegKey ; $RegKeyName ; expected value: $RegKeyValue ; current value: $tempRegKeyValue ; $tempRegKeyValueKind" )
                    write-host "$RegKey ; $RegKeyName ; expected value: $RegKeyValue ; current value: $tempRegKeyValue ; $tempRegKeyValueKind"
                }
            } else {
                LogError("$RegKey ; $RegKeyName ; expected value: $RegKeyValue ; current value: unknown")
            }
        } else {
            LogError("$RegKey ; $RegKeyName ; expected value: $RegKeyValue ; current value: unknown")
        }
        
    }
}

function Set-RegKeyValue
{
    [CmdletBinding()]
    param (
        [Parameter(Mandatory=$true)]
        [string]$Regkey,
        [Parameter(Mandatory=$true)]
        [string]$RegKeyName,
        [Parameter(Mandatory=$true)]
        [string]$RegKeyValue
    )
    process {
        if (test-path $Regkey)
        {
            $tempRegKey = Get-Item -LiteralPath $Regkey
            if ($null -ne $tempRegKey.GetValue($RegKeyName, $null)) {
                if ($PassThru) {
                    Get-ItemProperty $Regkey $RegKeyName
                } else {
                    Log("$RegKey ; $RegKeyName ; $RegKeyValue" )
                    Set-ItemProperty -Path $Regkey -Name $RegKeyName -Value $RegKeyValue
                }
            } else {
                LogError("Not able to write $RegKey ; $RegKeyName ; $RegKeyValue")
            }
        } else {
            LogError("Not able to write $RegKey ; $RegKeyName ; $RegKeyValue")
        }
        
    }
}


#MAIN

$SecHardValue = Import-Csv -Path $CSVInputPath
If ($HardCheck -eq "check")
{
    foreach ($SecValue in $SecHardValue)
    {    
        If ($SecValue.Type -eq "Registry"){
        Get-RegKeyValue -Regkey $SecValue.Location -RegKeyName $SecValue.ValueName -RegKeyValue $SecValue.Value
        }
    }
}elseif ($HardCheck -eq "insert")
{
    Write-Host "###############################" -ForegroundColor Red
    Write-Host "WARNING - HARDINING WILL BE SET" -ForegroundColor Red
    Write-Host "###############################" -ForegroundColor Red
    Read-Host -Prompt "Press any key to continue or CTRL+C to quit" 
    foreach ($SecValue in $SecHardValue)
        { 
            
            If ($SecValue.Type -eq "Registry"){
            Set-RegKeyValue -Regkey $SecValue.Location -RegKeyName $SecValue.ValueName -RegKeyValue $SecValue.Value
        }
    }
}