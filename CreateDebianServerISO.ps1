#
# Copyright (C) 2019 Tomasz Walczyk
#
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.
#
###########################################################

<#
.SYNOPSIS
  Creates unattended Debian server installer.
.DESCRIPTION
  Script will create Debian server installer from the latest minimal CD available.
  This can be changed by specifying -SourceURL and -ISONamePattern arguments.
  Files will be saved to the script directory unless -OutputDir was specified.
  All parameters are optional but missing configuration needs to provided during
  server installation. Installer will use first SCSI/SATA hard disk (/dev/sda).
.INPUTS
  None.
.OUTPUTS
  None.
.LINK
  https://github.com/tomasz-walczyk/create-debian-server-iso
.LINK
  https://github.com/tomasz-walczyk/create-debian-iso
.LINK
  https://github.com/tomasz-walczyk/windows-mkpasswd
#>
[CmdletBinding(PositionalBinding=$False)]
param (
  # Root SSH key password.
  # Supported values:
  # - RAND) : Generate random password.
  # - READ) : Read password from standard input.
  # - *)    : Use argument value as a password.
  [Parameter()]
  [ValidateScript({
    return (($_.length -gt 4 -and $_.length -lt 128) -or ($_ -eq "RAND") -or ($_ -eq "READ") -or (-not $_))
  })]
  [Alias("K")]
  [String]
  $KeyPassword,

  # Root account password.
  # Supported values:
  # - RAND) : Generate random password.
  # - READ) : Read password from standard input.
  # - *)    : Use argument value as a password.
  [Parameter()]
  [ValidateScript({
    return (($_.length -gt 4 -and $_.length -lt 128) -or ($_ -eq "RAND") -or ($_ -eq "READ") -or (-not $_))
  })]
  [Alias("A")]
  [String]
  $AccountPassword,

  # Enable full disk encryption.
  [Parameter()]
  [Alias("E")]
  [Switch]
  $Encrypt,

  # Server hostname.
  [Parameter()]
  [ValidatePattern("^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$")]
  [Alias("H")]
  [String]
  $Hostname,

  # Server domain.
  [Parameter()]
  [ValidatePattern("^[a-zA-Z0-9][a-zA-Z0-9.-]{0,61}[a-zA-Z0-9]$")]
  [Alias("D")]
  [String]
  $Domain,

  # Path to the output directory.
  [Parameter()]
  [ValidateScript({
    $Path=$ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($_)
    if (Test-Path $Path) {
      return (Test-Path $Path -PathType Container) -and ((Get-ChildItem $Path | Measure-Object).Count -eq 0)
    } else {
      return (Split-Path $Path | Test-Path -PathType Container)
    }
  })]
  [Alias("O")]
  [String]
  $OutputDir=(Join-Path $PSScriptRoot (Get-Date -UFormat "debian-server_%Y-%m-%d_%H-%M-%S")),

  # Source URL from where ISO should be downloaded.
  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [Alias("S")]
  [String]
  $SourceURL,

  # Regular expression for selecting ISO file.
  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [Alias("I")]
  [String]
  $ISONamePattern,

  # Additional installer boot flags.
  [Parameter()]
  [ValidateNotNullOrEmpty()]
  [Alias("B")]
  [String]
  $BootFlags
)

###########################################################

Set-StrictMode -Version Latest

###########################################################

function New-RandomPassword([Int]$Length) {
    $Password=$Null
    if ($Length) {
        Get-Random -count $Length -input (48..57 + 65..90 + 97..122) | ForEach-Object { $Password+=[Char]$_ }
    }
    return $Password
}

#----------------------------------------------------------

function Join-Paths([String[]]$Paths) {
    if (!$Paths -or !$Paths.Count) {
        return $Null
    } else {
        $Path=$Paths[0]
        for ($Index=1; $Index -lt $Paths.Count; $Index+=1) {
            $Path=Join-Path $Path $Paths[$Index]
        }
        return $Path
    }
}

###########################################################

$TempDir=New-TemporaryFile | ForEach-Object { Remove-Item $_; New-Item $_ -ItemType Directory }

###########################################################

# try 
# {
#     #------------------------------------------------------
#     # Define all needed files and directories.
#     #------------------------------------------------------

#     $KeyType="RSA"
#     $KeyBits=4092
#     $MinPasswordLength=5
#     $MaxPasswordLength=127
#     $RandPasswordLength=32

#     $HostLabel=if ($Hostname) { $Hostname } else { "server" }
#     $UserLabel=if ($Username) { $Username } else { "root" }

#     $ISOFile=Join-Paths $OutputDir,"$HostLabel.iso"
#     $PreseedFile=Join-Paths $OutputDir,"$HostLabel.seed"
#     $AttachmentDir=Join-Paths $OutputDir,"$HostLabel"
#     $AttachmentFile=Join-Paths $OutputDir,"$HostLabel.tar.gz"
#     $PasswordsFile=Join-Paths $OutputDir,"$UserLabel@$HostLabel.pass"
#     $PrivateKeyFile=Join-Paths $OutputDir,"$UserLabel@$HostLabel"
#     $PublicKeyFile=Join-Paths $OutputDir,"$UserLabel@$HostLabel.pub"

#     #------------------------------------------------------
#     # Configure output directory.
#     #------------------------------------------------------

#     $DirToRemoveOnExit=$OutputDir

#     if (-not (Test-Path $OutputDir)) {
#         $Path=New-Item $OutputDir -ItemType Directory
#     }

#     if (-not (Test-Path $AttachmentDir)) {
#         $Path=New-Item $AttachmentDir -ItemType Directory
#     }

#     #------------------------------------------------------
#     # Configure full disk encryption.
#     #------------------------------------------------------

#     if ($Encrypt) {
#         Copy-Item (Join-Paths $PSScriptRoot,"data","debian-server-crypt.seed") $PreseedFile
#     } else {
#         Copy-Item (Join-Paths $PSScriptRoot,"data","debian-server.seed") $PreseedFile
#     }

#     #------------------------------------------------------
#     # Configure hostname.
#     #------------------------------------------------------

#     if ($Hostname) {
#         (Get-Content $PreseedFile).replace("{{HOSTNAME}}", $Hostname) | Set-Content $PreseedFile
#     } else {
#         (Get-Content $PreseedFile) | Select-String -pattern "{{HOSTNAME}}" -notmatch | Set-Content $PreseedFile
#     }

#     #------------------------------------------------------
#     # Configure domain.
#     #------------------------------------------------------

#     if ($Domain) {
#         (Get-Content $PreseedFile).replace("{{DOMAIN}}", $Domain) | Set-Content $PreseedFile
#     } else {
#         (Get-Content $PreseedFile) | Select-String -pattern "{{DOMAIN}}" -notmatch | Set-Content $PreseedFile
#     }

#     #------------------------------------------------------
#     # Configure account details.
#     #------------------------------------------------------

#     if ($Username) {
#         (Get-Content $PreseedFile).replace("{{MAKE_ROOT}}", "false") | Set-Content $PreseedFile
#         (Get-Content $PreseedFile).replace("{{MAKE_USER}}", "true") | Set-Content $PreseedFile
#         (Get-Content $PreseedFile).replace("{{USERNAME}}", $Username) | Set-Content $PreseedFile
#         (Get-Content $PreseedFile).replace("{{FULLNAME}}", $Fullname) | Set-Content $PreseedFile
#         (Get-Content $PreseedFile).replace("{{USER_PASSWORD}}", "{{PASSWORD}}") | Set-Content $PreseedFile
#         (Get-Content $PreseedFile) | Select-String -pattern "{{ROOT_PASSWORD}}" -notmatch | Set-Content $PreseedFile
#     } else {
#         (Get-Content $PreseedFile).replace("{{MAKE_ROOT}}", "true") | Set-Content $PreseedFile
#         (Get-Content $PreseedFile).replace("{{MAKE_USER}}", "false") | Set-Content $PreseedFile
#         (Get-Content $PreseedFile).replace("{{ROOT_PASSWORD}}", "{{PASSWORD}}") | Set-Content $PreseedFile
#         (Get-Content $PreseedFile) | Select-String -pattern "{{USERNAME}}" -notmatch | Set-Content $PreseedFile
#         (Get-Content $PreseedFile) | Select-String -pattern "{{FULLNAME}}" -notmatch | Set-Content $PreseedFile
#         (Get-Content $PreseedFile) | Select-String -pattern "{{USER_PASSWORD}}" -notmatch | Set-Content $PreseedFile
#     }

#     #------------------------------------------------------
#     # Configure account password.
#     #------------------------------------------------------

#     if ($AccountPassword -eq "READ") {
#         Write-Host ""
#         Write-Host "+-----------------------------------------------+"
#         Write-Host "|         Account password configuration        |"
#         Write-Host "+-----------------------------------------------+"
#         Write-Host ""

#         while ($True) {
#             $Password1=Read-Host -Prompt "Enter passphrase (empty for no passphrase)" -AsSecureString
#             $Password2=Read-Host -Prompt "Enter same passphrase again" -AsSecureString

#             $Password1=[System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password1))
#             $Password2=[System.Runtime.InteropServices.Marshal]::PtrToStringAuto([System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($Password2))

#             if ($Password1 -ne $Password2) {
#                 Write-Host "Passphrases do not match.  Try again."
#             } elseif ($Password1.length -gt 0 -and $Password1.length -lt $MinPasswordLength) {
#                 Write-Host "Passphrase is too short (minimum $MinPasswordLength characters).  Try again."
#             } elseif ($Password1.length -gt $MaxPasswordLength) {
#                 Write-Host "Passphrase is too long (maximum $MaxPasswordLength characters).  Try again."
#             } else {
#                 $AccountPassword=$Password1
#                 $Password1=$Null
#                 $Password2=$Null
#                 break
#             }
#         }
#     } elseif ($AccountPassword -eq "RAND") {
#         $AccountPassword=(New-RandomPassword $RandPasswordLength)
#         "Login   : $AccountPassword"| Out-File $PasswordsFile -Append
#     }

#     if ($AccountPassword) {
#         $mkpasswd=Join-Paths $PSScriptRoot,"data","mkpasswd-win","release","bin","mkpasswd-win.exe"
#         $PasswordHash=($AccountPassword | & $mkpasswd)
#         if ($LastExitCode -ne 0) {
#             throw "Command 'mkpasswd' failed with exit code: $LastExitCode"
#         }
#         (Get-Content $PreseedFile).replace("{{PASSWORD}}", $PasswordHash) | Set-Content $PreseedFile
#     } else {
#         (Get-Content $PreseedFile) | Select-String -pattern "{{PASSWORD}}" -notmatch | Set-Content $PreseedFile
#     }

#     $AccountPassword=$Null

#     #------------------------------------------------------
#     # Configure remote access.
#     #------------------------------------------------------

#     if ($KeyPassword -eq "READ") {
#         Write-Host ""
#         Write-Host "+-----------------------------------------------+"
#         Write-Host "|        SSH key password configuration         |"
#         Write-Host "+-----------------------------------------------+"
#         Write-Host ""

#         while ($True) {
#             & ssh-keygen -q -t $KeyType -b $KeyBits -f $PrivateKeyFile -C "$UserLabel@$HostLabel" 2> $Null
#             if ($LastExitCode -ne 0) {
#                 Write-Host "Passphrase is too short (minimum $MinPasswordLength characters).  Try again."
#             } else {
#                 Copy-Item $PublicKeyFile $AttachmentDir
#                 break
#             }
#         }
#     } elseif ($KeyPassword) {
#         if ($KeyPassword -eq "RAND") {
#             $KeyPassword=(New-RandomPassword $RandPasswordLength)
#             "SSH Key : $KeyPassword" | Out-File $PasswordsFile -Append
#         }

#         & ssh-keygen -q -t $KeyType -b $KeyBits -f $PrivateKeyFile -N "$KeyPassword" -C "$UserLabel@$HostLabel"
#         if ($LastExitCode -ne 0) {
#             throw "Command 'ssh-keygen' failed with exit code: $LastExitCode"
#         } 
#         Copy-Item $PublicKeyFile $AttachmentDir
#     }

#     $KeyPassword=$Null

#     #------------------------------------------------------
#     # Configure setup script.
#     #------------------------------------------------------

#     Copy-Item (Join-Paths $PSScriptRoot,"data","setup.sh") $AttachmentDir

#     #------------------------------------------------------
#     # Calculate attachments checksums.
#     #------------------------------------------------------

#     $AttachmentDirHash=Get-ChildItem $AttachmentDir -Recurse | Where-Object { Test-Path $_.FullName -PathType Leaf } | Get-FileHash -Algorithm SHA512
#     foreach ($Hash in $AttachmentDirHash) {
#         $Hash.Hash.ToLower() + "  " + $Hash.Path.Replace($AttachmentDir,"").Replace("\", "") | Out-File (Join-Paths $AttachmentDir,"SHA512SUMS") -Append
#     }

#     #------------------------------------------------------
#     # Create attachments archive.
#     #------------------------------------------------------

#     Push-Location $AttachmentDir
#     $7zip=Join-Paths $PSScriptRoot,"data","7zip","7z.exe"
#     & $7zip a -ttar -so "tmp.tar" * | & $7zip a -si $AttachmentFile 2>&1 > $Null
#     if ($LastExitCode -ne 0) {
#         throw "Command '7zip' failed with exit code: $LastExitCode"
#     }
#     Pop-Location
#     Remove-Item $AttachmentDir -Recurse

#     #------------------------------------------------------
#     # Create debian server ISO.
#     #------------------------------------------------------

#     Write-Host ""
#     Write-Host "+-----------------------------------------------+"
#     Write-Host "|           Creating server installer           |"
#     Write-Host "+-----------------------------------------------+"
#     Write-Host ""

#     $CreateDebianISO=Join-Paths $PSScriptRoot,"data","create-debian-iso","CreateDebianISO.ps1"
#     $CreateDebianISO+=" -PreseedFile `"$PreseedFile`""
#     $CreateDebianISO+=" -AttachmentFile `"$AttachmentFile`""
#     $CreateDebianISO+=" -OutputFile `"$ISOFile`""
#     if ($SourceURL) { $CreateDebianISO+=" -SourceURL `"$SourceURL`"" }
#     if ($BootFlags) { $CreateDebianISO+=" -BootFlags `"$BootFlags`"" }
#     if ($ISONamePattern) { $CreateDebianISO+=" -ISONamePattern `"$ISONamePattern`"" }
#     Invoke-Expression $CreateDebianISO

#     #------------------------------------------------------
#     # Calculate output files checksums.
#     #------------------------------------------------------

#     $OutputDirHash=Get-ChildItem $OutputDir -Recurse | Where-Object { Test-Path $_.FullName -PathType Leaf } | Get-FileHash -Algorithm SHA512
#     foreach ($Hash in $OutputDirHash) {
#         $Hash.Hash.ToLower() + "  " + $Hash.Path.Replace($OutputDir,"").Replace("\", "") | Out-File (Join-Paths $OutputDir,"SHA512SUMS") -Append
#     }

#     $DirToRemoveOnExit=$Null
# }
# catch 
# {
#     Write-Error $_.Exception.Message
# }
# finally
# {
#     if ($DirToRemoveOnExit -and (Test-Path $DirToRemoveOnExit)) {
#         Remove-Item $DirToRemoveOnExit -Force -Recurse
#     }
# }
