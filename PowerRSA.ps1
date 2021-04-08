﻿# http://www.di-mgt.com.au/rsa_alg.html
Param
    (
        [Parameter(Position=0,mandatory=$true)]    
        [String] $Method,
        [Parameter(Position=1,mandatory=$false)]    
        $Data,
        [Parameter(Position=2,mandatory=$false)]    
        [String] $Exponent,
        [Parameter(Position=3,mandatory=$false)]    
        [String] $Modulus,
        [Parameter(Position=4,mandatory=$false)]    
        [String] $KeyType
    )
function Get-GCD {

    [CmdletBinding()]
        Param (
            [Int64] $a, 
            [Int64] $b
        ) 
    while ($a -ne $b) {
        if ($a -gt $b) {
            $a = $a - $b
        }
        else {
            $b = $b - $a
        }
    }
    return $a;    
}

function Get-ExtendedEuclide($e, $PHI) {
    $u = @(1,0,$PHI)
    $v = @(0,1,$e)                
    while ($v[2] -ne 0) {        
        $q = $u[2] / $v[2]
        $temp1 = $u[0] - $q * $v[0]
        $temp2 = $u[1] - $q * $v[1]
        $temp3 = $u[2] - $q * $v[2]
        $u[0] = $v[0]
        $u[1] = $v[1]
        $u[2] = $v[2]
        $v[0] = $temp1
        $v[1] = $temp2
        $v[2] = $temp3
    }
    if ($u[1] -lt 0) {return ($u[1] + $PHI)}
    else {return ($u[1])}
}

function Get-RandomByte
{
    Param (
        [Parameter(Mandatory = $True)]
        [UInt32] $Length,
        [Parameter(Mandatory = $True)]
        [ValidateSet('GetRandom', 'CryptoRNG')]
        [String] $MethodRand,
        [Parameter(Mandatory = $False)]
        [Int32] $Minimum
    )

    $RandomBytes = New-Object Byte[]($Length)
 
    if(!$Minimum) {
        $Minimum = 0
    }

    switch ($MethodRand)
    {
        'GetRandom' {
            foreach ($i in 0..($Length - 1))
            {
                $RandomBytes[$i] = Get-Random -Minimum 0 -Maximum 256
            }
         }
         'CryptoRNG' {
             $RNG = [Security.Cryptography.RNGCryptoServiceProvider]::Create()
             $RNG.GetBytes($RandomBytes)
         }
    }
    $RandomBytes
}

function Is-PrimeRabinMiller {
[CmdletBinding()]
        Param (
            [BigInt] $Source, 
            [int] $Iterate
        ) 
    if ($source -eq 2 -or $source -eq 3) {
        return $true;
    }

    if (($source -lt 2) -or (($source % 2) -eq 0)) {
        return $false;
    }
 
    [BigInt]$d = $source - 1;
    $s = 0;
 
    while (($d % 2) -eq 0) {
        $d /= 2;
        $s++;
    }
 
    if ($source.ToByteArray().LongLength -gt 255) {
        $sourceLength = 255
    }
    else {
        $sourceLength = $source.ToByteArray().LongLength
    }

    [Byte[]] $bytes = $sourceLength 

    $rngProv = [System.Security.Cryptography.RNGCryptoServiceProvider]::Create()
    
    [BigInt]$a = 0
    for ($i = 0; $i -lt $Iterate; $i++) {          
        do {
            $rngProv.GetBytes($bytes)
            $a = [BigInt]$bytes            
        } while (($a -lt 2) -or ($a -ge ($source - 2)))                              
         
        [BigInt]$x = ([BigInt]::ModPow($a,$d,$source))
        if ($x -eq 1 -or ($x -eq $source-1)) {
            continue;
        }
 
        for ($j = 1; $j -lt $s; $j++) {            
            $x = [BigInt]::ModPow($x, 2, $source)
            if ($x -eq 1) {
                return $false;
            }
            if ($x -eq $source-1) {
                break
            }
        }
        return $false;
    }
    return $true;
}

function Get-RandomPrimeNumber {
    [CmdletBinding()]
    Param (
        [UInt32] $Length            
    ) 
    
    $prime = $false 
    for(!$prime) {
        $CryptoRNGBytes = Get-RandomByte -Method CryptoRNG -Length $Length
        $generated = ""        
        foreach($cryptoRNGByte in $CryptoRNGBytes) {
            $generated += $cryptoRNGByte
        }

        [BigInt]$generatedPrime = $generated
        $prime = Is-PrimeRabinMiller $generatedPrime 40
        if($prime -eq $true) {
            Break
        }
    }
    return $generatedPrime
}

function Write-Log {
    [CmdletBinding()]  
    Param ([Parameter(Mandatory=$true)][System.IO.StreamWriter]$StreamWriter, [Parameter(Mandatory=$true)][string]$InfoToLog)  
    Process{    
        try{
            $StreamWriter.WriteLine("$InfoToLog")
        }
        catch {
            $_
        }
    }
}

function End-Log { 
    [CmdletBinding()]  
    Param ([Parameter(Mandatory=$true)][System.IO.StreamWriter]$StreamWriter)  
    Process{             
        $StreamWriter.Close()   
    }
}

$scriptPath = split-path -parent $MyInvocation.MyCommand.Definition
$scriptParentPath = split-path -parent $scriptPath
$scriptFile = $MyInvocation.MyCommand.Definition
$launchDate = get-date -f "yyyyMMddHHmmss"
$logDirectoryPath = $scriptPath + "\" + $launchDate

$privateKeyFile = "PrivateKey"
$publicKeyFile = "PublicKey"
$modulusFile = "Modulus"
$dataFile = "Data"
$privateKeyFileName = "$logDirectoryPath\$privateKeyFile"
$publicKeyFileName = "$logDirectoryPath\$publicKeyFile"
$modulusFileName = "$logDirectoryPath\$modulusFile"
$dataFileName = "$logDirectoryPath\$dataFile"

$gen = 0
$encrypt = 0
$decrypt =0
$nothing = 0

Switch ($Method) {
    'GenKeys' { $gen = 1}
    'Enc' { $encrypt = 1}
    'Dec' { $decrypt = 1}
    default { $nothing = 1}
}

if ($nothing -eq 1) {
    Write-Output "Unrecognized mnethod"
    Exit
}
if ($gen -eq 1) {
    if(!(Test-Path $logDirectoryPath)) {
        New-Item $logDirectoryPath -type directory | Out-Null
    }
    $streamWriterPrivate = New-Object System.IO.StreamWriter $privateKeyFileName
    $streamWriterPublic = New-Object System.IO.StreamWriter $publicKeyFileName
    $streamWriterModulus = New-Object System.IO.StreamWriter $modulusFileName
    Write-Output "Keys generating..."   
    [UInt32]$Length = 0x80
    Switch ($KeyType) {
        '1024-bit' {$Length = 0x40}
        '2048-bit' {$Length = 0x80}        
        '4096-bit' {$Length = 0x100}        
        default {$Length = 0x80}
    }

    [BigInt]$p = Get-RandomPrimeNumber -Length $Length   
    [BigInt]$q = Get-RandomPrimeNumber -Length $Length   

    if($q -ge $p) {    
        [BigInt]$temp = $p
        $p = $q
        $q = $temp
    }

    [BigInt]$n = $p * $q    

    [BigInt]$PHI = ($p-1)*($q-1)

    $e = 65537
    
    Write-Log -streamWriter $streamWriterPublic -infoToLog "$($e.ToString("X"))"
    

    [BigInt]$d = Get-ExtendedEuclide $e $PHI

    $dString = $d.ToString("X")
    $nString = $n.ToString("X")
 
    Write-Log -StreamWriter $streamWriterPrivate -InfoToLog "$dString"
    Write-Log -StreamWriter $streamWriterModulus -InfoToLog "$nString" 

    End-Log -StreamWriter $streamWriterPublic
    End-Log -StreamWriter $streamWriterPrivate
    End-Log -StreamWriter $streamWriterModulus

    Write-Output "Keys saved in $logDirectoryPath"
}

if($encrypt -eq 1) {    
    if(!(Test-Path $logDirectoryPath)) {
        New-Item $logDirectoryPath -type directory | Out-Null
    }
    $streamWriterData = New-Object System.IO.StreamWriter $dataFileName
    if(![String]::IsNullOrWhiteSpace($Modulus)) {
        if(![String]::IsNullOrWhiteSpace($Exponent)) {
            $exponentContent = Get-Content $Exponent            
            $modulusContent = Get-Content $Modulus
            [BigInt]$exponentInt = [BigInt]::Parse($exponentContent,([System.Globalization.NumberStyles]::HexNumber));
            $modulusInt = [BigInt]::Parse($modulusContent,([System.Globalization.NumberStyles]::HexNumber));
            
            $message = Read-Host 'Enter message to encrypt'	    

            $tabChar = $message[0..$message.length]
            $i = 0
            $encodedString = ""
            foreach ($character in $tabChar){    
                $asciiCode = [int]$character[-0]	

                # Create a random padding before encrypt data to avoid statistical attack on text
                $CryptoRNGBytes = Get-RandomByte -Method CryptoRNG -Length 0x12
                [string]$randomPadding = ""
                foreach($c in $CryptoRNGBytes) {
                    $randomPadding += $c
                }

                [BigInt]$asciiCode = "$($asciiCode)00005$randomPadding"
    
                $cryptCharacter = ([BigInt]::ModPow($asciiCode,$exponentInt,$modulusInt))
    
                <#
                if ($asciiCode -gt $n) {
                    Write-Output "p and q number too small, try again"
                }
                if ([int]$cryptCharacter -gt $PHI) {
                    Write-Output "$cryptCharacter Calculation error"
                }
                #>
                if($i -eq 0) {
                    $encodedString = $cryptCharacter.ToString("X")
                }
                else {
                    $encodedString += ",$($cryptCharacter.ToString("X"))"
                }    
                $i = $i + 1
            }

            # Write-Output $encodedString
            Write-Log -StreamWriter $streamWriterData -InfoToLog "$encodedString" 
            End-Log -StreamWriter $streamWriterData

            Write-Output "Data saved in $logDirectoryPath"
        }        
        else {
            Write-Output "You have to enter the Exponent to encrypt data"
        }
    }
    else {
        Write-Output "You have to enter the Modulus to encrypt data"
    }
}

if($decrypt -eq 1) {
    if(($Data)) {
        if(![String]::IsNullOrWhiteSpace($Modulus)) {
            if(![String]::IsNullOrWhiteSpace($Exponent)) {
                    $exponentContent = Get-Content $Exponent            
                    $modulusContent = Get-Content $Modulus
                    $dataContent = Get-Content $Data
                    $d = [BigInt]::Parse($exponentContent,([System.Globalization.NumberStyles]::HexNumber));        
                    $n = [BigInt]::Parse($modulusContent,([System.Globalization.NumberStyles]::HexNumber));                            
                    $block = $dataContent
                    $block = $block -split ","                    
                    $string = "" 
                    foreach ($b in $block) {
                        $b = [BigInt]::Parse($b,([System.Globalization.NumberStyles]::HexNumber));        
                        [BigInt]$asciiCode = ([BigInt]::ModPow($b,$d,$n))

                        $asciiCodeSplitted = $asciiCode -split "00005"
                        [int]$asciiCodeSplittedInteger = $asciiCodeSplitted[0]

                        $string = $string + $([char]$asciiCodeSplittedInteger)
                    }

                    Write-Output $string       
            }              
            else {
                Write-Output "You have to enter the private Exponent to decrypt data"
            }
        }
        else {
            Write-Output "You have to enter the Modulus to decrypt data"
        }
    }
    else {
        Write-Output "You have to enter the data to decrypt"
    }
}
