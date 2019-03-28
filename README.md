Creates unattended Debian server installer.
___
### LINUX
Script will create Debian server installer from the latest minimal CD available.
This can be changed by specifying `--source-url` and `--iso-name-pattern` arguments.
Files will be saved to the script directory unless `--output-dir` was specified.
All parameters are optional but missing configuration needs to provided during
server installation. Installer will use first SCSI/SATA hard disk (`/dev/sda`).
#### Setup:
```bash
git clone https://github.com/tomasz-walczyk/create-debian-server-iso.git
cd create-debian-server-iso
chmod +x create-debian-server-iso.bash
```
#### Create installer:
```bash
./create-debian-server-iso.bash --encrypt --key-password READ --account-password READ --hostname "<hostname>" --domain "<domain>" --output-dir "<path>"
```
#### Display help:
```bash
./create-debian-server-iso.bash --help
```
___
### WINDOWS
Script will create Debian server installer from the latest minimal CD available.
This can be changed by specifying `-SourceURL` and `-ISONamePattern` arguments.
Files will be saved to the script directory unless `-OutputDir` was specified.
All parameters are optional but missing configuration needs to provided during
server installation. Installer will use first SCSI/SATA hard disk (`/dev/sda`).
#### Setup:
```powershell
git clone https://github.com/tomasz-walczyk/create-debian-server-iso.git
Set-Location create-debian-server-iso
Set-ExecutionPolicy Bypass -Scope Process
```
#### Create installer:
```powershell
.\CreateDebianServerISO.ps1 -Encrypt -KeyPassword READ -AccountPassword READ -Hostname "<hostname>" -Domain "<domain>" -OutputDir "<path>"
```
#### Display help:
```powershell
Get-Help .\CreateDebianServerISO.ps1 -Full
```
___
*Copyright (C) 2019 Tomasz Walczyk*

*This software may be modified and distributed under the terms*
*of the MIT license. See the [LICENSE](LICENSE) file for details.*
