function Get-JotFormApiKey {
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$ApiKey,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$RegistryKeyPath = 'HKCU:\Software\PSJotForm'
	)
	
	$ErrorActionPreference = 'Stop'

	function decrypt([string]$TextToDecrypt) {
		$secure = ConvertTo-SecureString $TextToDecrypt
		$hook = New-Object system.Management.Automation.PSCredential("test", $secure)
		$plain = $hook.GetNetworkCredential().Password
		return $plain
	}

	try {
		if ($PSBoundParameters.ContainsKey('ApiKey')) {
			$script:JotFormAPIKey = $ApiKey
			$script:JotFormAPIKey
		} elseif (Get-Variable -Name JotFormAPIKey -Scope Script -ErrorAction Ignore) {
			$script:JotFormAPIKey
		} elseif (-not (Test-Path -Path $RegistryKeyPath)) {
			throw "No JotForm configuration found in registry"
		} elseif (-not ($keyValues = Get-ItemProperty -Path $RegistryKeyPath)) {
			throw 'JotForm API not found in registry'
		} else {
			$script:JotFormAPIKey = decrypt $keyValues.APIKey
			$script:JotFormAPIKey
		}
	} catch {
		Write-Error $_.Exception.Message
	}
}

function Get-MindMeisterApiAuthInfo {
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[string]$PersonalAccessToken,

		[Parameter()]
		[string]$SharedKey,

		[Parameter()]
		[string]$SecretKey,

		[Parameter()]
		[string]$V1Token,

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
		if (-not $script:mindMeisterApiInfo) {
			$script:mindMeisterApiInfo = [pscustomobject]@{}
		}
		
		$params = 'PersonalAccessToken', 'SharedKey', 'SecretKey', 'V1Token'
		foreach ($param in $params) {
			if ($PSBoundParameters.ContainsKey($param)) {
				Write-Verbose -Message "Found API val [$($param)] in passed parameter."
				$script:mindMeisterApiInfo | Add-Member -NotePropertyName $param -NotePropertyValue (Get-Variable -Name $param).Value -Force
			} elseif ($param -notin $script:mindMeisterApiInfo.PSObject.Properties.Name) {
				if ($value = Get-ItemProperty -Path $RegistryKeyPath -Name $params -ErrorAction Ignore) {
					Write-Verbose -Message "Found API val [$($param)] in registry."
					$script:mindMeisterApiInfo | Add-Member -NotePropertyName $param -NotePropertyValue (decrypt $value.$param)
				} else {
					throw "The [$($param)] MindMeister API value could not be found."
				}
			} else {
				Write-Verbose -Message "Found API val [$($param)] in existing script variable."
			}
		}
		$script:mindMeisterApiInfo
	} catch {
		Write-Error $_.Exception.Message
	}
}

function Save-MindMeisterApiAuthInfo {
	[CmdletBinding()]
	param (
		[Parameter()]
		[string]$V2PersonalAccessToken,

		[Parameter()]
		[string]$SharedKey,

		[Parameter()]
		[string]$SecretKey,

		[Parameter()]
		[string]$V1Token,
	
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

function Get-MindMeisterApiV1Signature {
	[OutputType('void')]
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[hashtable]$Parameters
	)

	$ErrorActionPreference = 'Stop'

	function Get-MD5Hash {
		param($String)

		$md5 = new-object -TypeName System.Security.Cryptography.MD5CryptoServiceProvider
		$utf8 = new-object -TypeName System.Text.UTF8Encoding
		([System.BitConverter]::ToString($md5.ComputeHash($utf8.GetBytes($String))) -replace '-').ToLower()
	}

	$secretKey = Get-MindMeisterApiAuthInfo | Select-Object -ExpandProperty SecretKey

	$paramsSorted  = [ordered]@{}
	$Parameters.Keys | Sort-Object | ForEach-Object {
		$paramsSorted[$_] = $Parameters[$_]
	}
	$paramString = ''
	$paramsSorted.GetEnumerator().foreach({
			$paramString += "$($_.Key)$($_.Value)"	
		})
	$paramString = "$($secretKey)$paramString"
	Get-MD5Hash -String $paramString	
}

function Connect-MindMeisterApiV1 {
	[OutputType('void')]
	[CmdletBinding()]
	param
	()

	$ErrorActionPreference = 'Stop'

	$script:frob = (Invoke-MindMeisterApiCallV1 -ApiMethod 'mm.auth.getFrob').frob

	$parameters = @{
		perms   = 'delete'
		api_key = (Get-MindMeisterApiAuthInfo | Select-Object -ExpandProperty SharedKey)
		frob    = $script:frob
	}
	$sig = Get-MindMeisterApiV1Signature -Parameters $parameters

	$paramString = ConvertTo-UriParameters -HttpBody $parameters

	$authUri = "http://www.mindmeister.com/services/auth/?$paramString&api_sig=$sig"
	Start-Process $authUri

	if ($token = (Invoke-MindMeisterApiCallV1 -ApiMethod 'mm.auth.getToken' -Parameters @{'frob' = $script:frob }).auth.token) {
		Save-MindMeisterApiAuthInfo -V1Token $token
	} else {
		throw 'Could not retrieve token.'
	}
	
}

function Invoke-MindMeisterApiCallV2 {
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
		[hashtable]$Payload
	)

	begin {
		$ErrorActionPreference = 'Stop'

		$apiCreds = Get-MindMeisterApiAuthInfo
	}
	process {

		$invRestParams = @{
			Method      = $HttpMethod
			Uri         = "https://www.mindmeister.com/api/v2/$Endpoint"
			Headers     = @{ 
				'Authorization' = "Bearer $($apiCreds.V2PersonalAccessToken)" 
				'Content-Type'  = 'application/json'
			}
			ErrorAction = 'Stop'
		}
		Invoke-RestMethod @invRestParams
	}
}

function ConvertTo-UriParameters {
	[OutputType('string')]
	[CmdletBinding()]
	param
	(
		[Parameter(Mandatory)]
		[ValidateNotNullOrEmpty()]
		[hashtable]$HttpBody
	)

	$ErrorActionPreference = 'Stop'

	$params = @()
	$HttpBody.GetEnumerator().foreach({
			$params += "$($_.Key)=$($_.Value)"
		})
	$params -join '&'
}

function Invoke-MindMeisterApiCallV1 {
	[OutputType('pscustomobject')]
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$ApiMethod,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[ValidateSet('auth', 'rest')]
		[string]$ApiService = 'rest',

		[Parameter()]
		[string]$HttpMethod = 'GET',

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[hashtable]$Parameters
	)

	$ErrorActionPreference = 'Stop'

	$paramsToSign = @{
		'api_key'         = (Get-MindMeisterApiAuthInfo).SharedKey
		'response_format' = 'xml'
	}
	if ($PSBoundParameters.ContainsKey('Parameters')) {
		$Parameters.GetEnumerator() | ForEach-Object {
			$paramsToSign[$_.Key] = $_.Value
		}	
	}
	if ($PSBoundParameters.ContainsKey('ApiMethod')) {
		$paramsToSign.method = $ApiMethod
		if ($ApiMethod -notlike 'mm.auth*') {
			$paramsToSign.auth_token = (Get-MindMeisterApiAuthInfo).V1Token
		}
	}
	
	$sig = Get-MindMeisterApiV1Signature -Parameters $paramsToSign
	$paramString = ConvertTo-UriParameters -HttpBody ($paramsToSign + @{'api_sig' = $sig})
	$uri = 'https://www.mindmeister.com/services/{0}?{1}' -f $ApiService, $paramString

	$invRestParams = @{
		Uri         = $uri
		Method      = $HttpMethod
		ErrorAction = 'Stop'
	}
	
	$result = Invoke-RestMethod @invRestParams
	if ($result.stat -eq 'fail') {
		throw $result.rsp.err.msg
	} else {
		$result.rsp
	}
}

function Get-MindMeisterMap {
	[OutputType('pscustomobject')]
	[CmdletBinding()]
	param
	(
		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[int]$Id,

		[Parameter()]
		[ValidateNotNullOrEmpty()]
		[string]$Name
	)

	$ErrorActionPreference = 'Stop'

	if ($PSBoundParameters.Keys.Count -eq 0) {
		(Invoke-MindMeisterApiCallV1 -ApiMethod 'mm.maps.getList').maps.map
	} elseif ($PSBoundParameters.ContainsKey('Name')) {
		$result = (Invoke-MindMeisterApiCallV1 -ApiMethod 'mm.maps.getList').maps.map
		if ($map = $result.where({ $_.title -eq $Name })) {
			Get-MindMeisterMap -Id $map.id
		}
	} elseif ($PSBoundParameters.ContainsKey('Id')) {
		Invoke-MindMeisterApiCallV1 -ApiMethod 'mm.maps.getMap' -Parameters @{ 'map_id' = $Id }
	}
}