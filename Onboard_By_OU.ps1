################################### GET-HELP #############################################
<#
.SYNOPSIS
	This script pull accounts from pending then attempt to onboard each account into a safe
	based on the OU it was discovered in.

	Please read through this script and the comments below and make changes as needed.

.EXAMPLE
	./Onboard_By_OU.ps1

.INPUTS
	None via command line

.OUTPUTS
	Log file

.NOTES
	AUTHOR:
	Randy Brown

	VERSION HISTORY:
	v0.1 - Initial release lab tested
	v0.2 - Added API call to delete all pending accounts
#>
##########################################################################################

######################### GLOBAL VARIABLE DECLARATIONS ###################################

# CHANGE ME
$baseURI = "https://components.cybrdemo.com"		# URL or IP address for your environment

########################## START FUNCTIONS ###############################################

function APILogin {
    param (
        $user,
        $pass
    )
	$data = @{
		username=$user
		password=$pass
		useRadiusAuthentication=$false
	}

	$loginData = $data | ConvertTo-Json

	Write-Debug "API Logon Data: $loginData"

	try {
		Write-Log $MyInvocation.MyCommand "Logging into EPV as $user..." $_ "info" $false $false
		
		$ret = Invoke-RestMethod -Uri "$BaseURI/PasswordVault/API/Auth/cyberark/Logon" -Method POST -Body $loginData -ContentType "application/json"
		
		Write-Host "OK" -ForegroundColor Green
	} catch {		
		Write-Log $MyInvocation.MyCommand $_.Exception.Message $_ "error" $false $true
	}
	return $ret
}
function APILogoff {
	try {
		Write-Log $MyInvocation.MyCommand "Logging off..." $_ "info" $false $false
		
		Invoke-RestMethod -Uri "$BaseURI/PasswordVault/API/Auth/Logoff" -Method POST -Headers $header -ContentType "application/json" | Out-Null
		
		Write-Host "OK" -ForegroundColor Green
	} catch {
		Write-Log $MyInvocation.MyCommand $_.Exception.Message $_ "error" $false $true
	}
}

function Get-DiscoveredAccounts {
	try {
		Write-Log $MyInvocation.MyCommand "Getting siscovered accounts..." $_ "info" $false $false

		# This API call will return any accounts in the pending list that match all the following...
		# 1) Windows Server Local Account
		# 2) Is a privileged account
		# 3) The account is enabled
		# 4) The username starts with admin
		$accounts = Invoke-RestMethod -Uri "$baseURI/PasswordVault/API/DiscoveredAccounts?filter=platformType eq Windows Server Local AND privileged eq true AND accountEnabled eq true&search=admin&searchType=contains&offset=0&limit=100" -Method Get -Headers $header -ContentType 'application/json'

		Write-Host "OK" -ForegroundColor Green

		return $accounts
	}
	catch {
		Write-Log $MyInvocation.MyCommand $_.Exception.Message $_ "error" $false $true
	}
}

function BuildAccountObject($account, $safe) {
	try {
		Write-Log $MyInvocation.MyCommand "Building data body on onboard account..." $_ "info" $false $false

		$platformID = "Windows_Domain_NonManaged" # CHANGE ME
		# For the $acctName variable the default format is <Device Type>-<Platform>-<Address>-<Username>
		# Please note, this string MUST be unique for each account. A combination of Username and Address will make it unique.
		$acctName = "Operating System-" + $platformID + "-" + $account.address + "-" + $account.userName 
		$data = @{
			name=$acctName
			address=$account.address
			userName=$account.userName
			platformId=$platformID
			safeName=$safe
			secretType="password"
			secret="SuperS3cr3t3P@55w0rd!" # This is a temp PW. The CPM will attempt to change this once the account has been onboarded.
			platformAccountProperties=@{
			}
			secretManagement=@{
				automaticManagementEnabled=$true
			}
		}

		$retData = $data | ConvertTo-Json

		Write-Host "OK" -ForegroundColor Green

		return $retData
	}
	catch {
		Write-Log $MyInvocation.MyCommand $_.Exception.Message $_ "error" $false $true
	}
}

function AccountOnboard($bodyData) {
	try {
		Write-Log $MyInvocation.MyCommand "Onboarding account..." $_ "info" $false $false

		Invoke-RestMethod -Uri "$baseURI/PasswordVault/api/Accounts" -Method Post -Headers $header -Body $bodyData -ContentType 'application/json'

		Write-Host "OK" -ForegroundColor Green
	}
	catch {
		Write-Log $MyInvocation.MyCommand $_.Exception.Message $_ "error" $false $false
	}	
}

function OnBoardAccounts {
	try {
		$accounts = Get-DiscoveredAccounts

		foreach ($account in $accounts.value) {
			Write-Host "########## Discovered Account ##########"
			# Please be sure to change the OUs to match your AD structure. 
			switch -Wildcard ($account.organizationalUnit) {
				"*CN=Computers,DC=cybrdemo,DC=com" {
					$acctData = "Account data:`nUserName = " + $account.userName + "`nAddress = " + $account.address + "`nOU = " + $account.organizationalUnit
					Write-Log $MyInvocation.MyCommand $acctData $_ "info" $false $false
					Write-Host ""
					$safe = "Servers" # CHANGE ME
					AccountOnboard $(BuildAccountObject $account $safe)
					break }

				# Add more OUs to match here with the needed safe name
				# "*CN=Computers,DC=cybrdemo,DC=com" { 
					# $safe = "Servers"
					# AccountOnboard $(BuildAccountObject $account $safe)
					# break }

				# Leave this Default response in place
				Default { Write-Host "Could not match OU for:"
					Write-Host "Username =" $account.userName
					Write-Host "OU =" $account.organizationalUnit }
			}

			Write-Host "########## END ##########"
		}
	}
	catch {
		Write-Log $MyInvocation.MyCommand $_.Exception.Message $_ "error" $false $true
	}
}

function Delete-DiscoveredAccounts {
	try {
		Invoke-RestMethod -Uri "$baseURI/PasswordVault/api/DiscoveredAccounts" -Method Delete -Headers $header -ContentType 'application/json'
	} catch {
		Write-Log $MyInvocation.MyCommand $_.Exception.Message $_ "error" $false $false
	}
}

function Write-Log {
    param
    (
	[string]$function,
        [string]$message,
	[System.Management.Automation.ErrorRecord]$errorObj,
        [string]$type,
	[bool]$logoff,
	[bool]$quitScript,
        [string]$logFolderPath = "$PSScriptRoot\Logs",
        [string]$logFilePrefix = 'Bulk_UO-Onboarding'
    )
 
    $date = Get-Date -Format "MM-dd-yyyy"
    $time = Get-Date -Format "HH:mm:ss.f"
    $logFile = "$LogFolderPath\$LogFilePrefix`_$date.log"
 
    if (!(Test-Path -Path $logFolderPath)) {
        New-Item -ItemType Directory -Path $logFolderPath -Force | Out-Null
    }
 
    if (!(Test-Path -Path $logFile)) {
        New-Item -ItemType File -Path $logFile -Force | Out-Null
    }
 
    $logMessage = "[$time] "
 
	switch ($type.ToLower()) {
		"error" { 
			if ($PSBoundParameters.ContainsKey("errorObj")) {
				$logMessage += "Error: $errorObj $($errorObj.ScriptStackTrace.Split("`n") -join ' <-- ')"
				$logMessage += "A error occured in `"$function`""
				$logMessage += $message
				Write-Error -Message $logMessage
			}
		} "warning" { 
			$logMessage += "Warning | $function | $message"
        	Write-Warning -Message $logMessage
		} "info" {
			$logMessage += "Info | $function | $message"
        	Write-Host $logMessage -NoNewline
		} "remote" {
            $logMessage += "Remote | $function | $($message.Split("`n") -join "`n[$time] Remote | $function | ")"
        }
	}
 
    Add-Content -Path $logFile -Value "$logMessage"

	if ($logoff) {
		APILogoff
	}

	if ($quitScript -and $type -eq "error" -or $type -eq "warning") {
		Write-Host "Stopping script" -ForegroundColor Yellow
		exit 1
	} elseif (!($quitScript) -and $type -eq "error" -or $type -eq "warning") {
		Write-Host "Moving on..." -ForegroundColor Yellow
	}
}
########################## END FUNCTIONS #################################################

########################## MAIN SCRIPT BLOCK #############################################

$user = Read-Host "CyberArk Username"
$securePassword = Read-Host "Password" -AsSecureString
$BSTR = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($securePassword)
$unsecurePassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($BSTR)
$login = EPVLogin $user $unsecurePassword

if ($login) {
    $header = New-Object "System.Collections.Generic.Dictionary[[String],[String]]"
    $header.Add("Authorization", $login)
	$securePassword = ""
	$unsecurePassword = ""
} else {
	Write-Log "Main" $_.Exception.Message $_ "error" $false $false
}

OnBoardAccounts
Delete-DiscoveredAccounts
EPVLogoff
########################### END SCRIPT ###################################################
