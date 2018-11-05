function Get-MindMeisterApiAuthInfo {
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$RegistryKeyPath = 'HKCU:\Software\PSMindMeister'
	)
	
	$ErrorActionPreference = 'Stop'

	function decrypt([string]$TextToDecrypt) {
		$secure = ConvertTo-SecureString $TextToDecrypt
		$hook = New-Object system.Management.Automation.PSCredential("test", $secure)
		$plain = $hook.GetNetworkCredential().Password
		return $plain
	}

	try {
		if (-not (Test-Path -Path $RegistryKeyPath)) {
			Write-Warning 'No PSMindMeister API info found in registry'
		} else {
			$keys = (Get-Item -Path $RegistryKeyPath).Property
			$ht = @{}
			foreach ($key in $keys) {
				$ht[$key] = decrypt (Get-ItemProperty -Path $RegistryKeyPath).$key
			}
			[pscustomobject]$ht
		}
	} catch {
		Write-Error $_.Exception.Message
	}
}

function Save-MindMeisterApiAuthInfo {
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]$PersonalAccessToken,
	
		[Parameter()]
		[string]$RegistryKeyPath = "HKCU:\Software\PSMindMeister"
	)

	begin {
		function encrypt([string]$TextToEncrypt) {
			$secure = ConvertTo-SecureString $TextToEncrypt -AsPlainText -Force
			$encrypted = $secure | ConvertFrom-SecureString
			return $encrypted
		}
	}
	
	process {
		if (-not (Test-Path -Path $RegistryKeyPath)) {
			New-Item -Path ($RegistryKeyPath | Split-Path -Parent) -Name ($RegistryKeyPath | Split-Path -Leaf) | Out-Null
		}
		
		$values = $PSBoundParameters.GetEnumerator().where({ $_.Key -ne 'RegistryKeyPath' -and $_.Value}) | Select-Object -ExpandProperty Key
		
		foreach ($val in $values) {
			Write-Verbose "Creating $RegistryKeyPath\$val"
			New-ItemProperty $RegistryKeyPath -Name $val -Value $(encrypt $((Get-Variable $val).Value)) -Force | Out-Null
		}
	}
}

function Invoke-MindMeisterApiCall {
	[OutputType('pscustomobject')]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[string]$Endpoint,

		[Parameter()]
		[string]$HttpMethod = 'GET',

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[int]$Version
	)

	$ErrorActionPreference = 'Stop'

	if (-not ($personalAccessToken = Get-MindMeisterApiAuthInfo | Select-Object -ExpandProperty PersonalAccessToken)) {
		throw 'Could not find personal access token'
	}

	if ($Version -eq 2) {
		$invRestParams = @{
			Method      = $HttpMethod
			Uri         = "https://www.mindmeister.com/api/v2/$Endpoint"
			Headers     = @{ 
				'Authorization' = "Bearer $personalAccessToken" 
				'Content-Type'  = 'application/json'
			}
			ErrorAction = 'Stop'
		}
	}

	Invoke-RestMethod @invRestParams
}

function Get-MindMeisterMap {
	[OutputType('pscustomobject')]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[int]$Id
	)

	$ErrorActionPreference = 'Stop'

	$invMMParams = @{ Endpoint = "maps/$Id" }

	Invoke-MindMeisterApiCall @invMMParams
}