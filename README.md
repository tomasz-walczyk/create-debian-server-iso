Creates unattended Debian server installer.
___
### LINUX
Script will create Debian server installer from the latest minimal CD available.
This can be changed by specifying --source-url and --iso-name-pattern arguments.
Files will be saved to the script directory unless --output-dir was specified.
All parameters are optional but missing configuration needs to provided during 
server installation. Encryption password cannot be preconfigured.
#### Warnings:
1. Installer will automatically use the first SCSI/SATA hard disk (/dev/sda).
2. Storing unencrypted SSH key is not secure!
3. Passing password as a command line argument is not secure!
4. Generation of a random password is not secure!
5. Sensitive information may be stored in the output directory!
#### Setup:
```bash
git clone --recurse-submodules https://twalczyk@bitbucket.org/twalczyk/create-debian-server-iso.git
cd create-debian-server-iso
chmod +x create-debian-server-iso.bash
```
#### Create installer:
```bash
sudo ./create-debian-server-iso.bash --encrypt --key-password READ --account-password READ --hostname <HOSTNAME> --domain <DOMAIN> --output-dir <PATH>
```
#### Display help:
```bash
./create-debian-server-iso.bash --help
```
#### Update
```bash
git pull
git submodule update --recursive --remote
```
___
### WINDOWS
Script will create Debian server installer from the latest minimal CD available.
This can be changed by specifying -SourceURL and ISONamePattern arguments.
Files will be saved to the script directory unless -OutputDir was specified.
All parameters are optional but missing configuration needs to provided during 
server installation. Encryption password cannot be preconfigured.
#### Warnings:
1. Installer will automatically use the first SCSI/SATA hard disk (/dev/sda).
2. Storing unencrypted SSH key is not secure!
3. Passing password as a command line argument is not secure!
4. Generation of a random password is not secure!
5. Sensitive information may be stored in the output directory!
#### Setup:
Install [Microsoft Visual C++ Redistributable for Visual Studio 2017 ](https://visualstudio.microsoft.com/downloads/) 
```powershell
git clone --recurse-submodules https://twalczyk@bitbucket.org/twalczyk/create-debian-server-iso.git
Set-Location create-debian-server-iso
Set-ExecutionPolicy Bypass -Scope Process
```
#### Create installer:
```powershell
.\CreateDebianServerISO.ps1 -Encrypt -KeyPassword READ -AccountPassword READ -Hostname <HOSTNAME> -Domain <DOMAIN> -OutputDir <PATH>
```
#### Display help:
```powershell
Get-Help .\CreateDebianServerISO.ps1 -Full
```
#### Update
```bash
git pull
git submodule update --recursive --remote
```
___
This software may be modified and distributed under the terms
of the MIT license. See the [LICENSE](LICENSE) file for details.
