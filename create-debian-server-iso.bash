#!/usr/bin/env bash
#
# Copyright (C) 2019 Tomasz Walczyk
#
# This software may be modified and distributed under the terms
# of the MIT license. See the LICENSE file for details.
#
###########################################################

set -o errexit
set -o nounset
set -o pipefail

###########################################################

[[ "$(uname -s)" != "Linux" ]] && { echo "Only Linux is supported!" >&2; exit 1; }
[[ "${BASH_VERSINFO}" -lt 4 ]] && { echo "Bash 4.0 is required!" >&2; exit 1; }
[[ "${EUID}" != 0 ]] && { echo "You need to run this script as root!" >&2; exit 1; }

###########################################################

readonly ScriptFile=$(readlink --canonicalize "${0}")
readonly ScriptName=$(basename "${ScriptFile}")
readonly ScriptRoot=$(dirname "${ScriptFile}")

###########################################################

readonly TempDir=$(mktemp --directory --tmpdir="/tmp" "${ScriptName}-XXXXXX")

###########################################################

readonly SSHKeyType=RSA
readonly SSHKeyBits=4092
readonly RandomPasswordLength=32
readonly MinimumPasswordLength=5
readonly MaximumPasswordLength=127

###########################################################

pushd() {
  command pushd "$@" > /dev/null
}

#----------------------------------------------------------

popd() {
  command popd "$@" > /dev/null
}

#----------------------------------------------------------

Failure() {
  if [[ ${#} -ne 0 ]]; then
    echo -e "${@}" >&2
  fi
  exit 1
}

#----------------------------------------------------------

Success() {
  if [[ ${#} -ne 0 ]]; then
    echo -e "${@}"
  fi
  exit 0
}

#----------------------------------------------------------

Clean() {
  if [[ -d "${TempDir}" ]]; then
    rm --recursive "${TempDir}"
  fi
}

#----------------------------------------------------------

CheckIfNotEmpty() {
  [[ -z "${1+x}" ]] && Failure "Identifier is required!"
  [[ -z "${2}" ]] && Failure "Invalid argument: \"${2}\" : Empty value!"
  echo -n "${2}"
}

#----------------------------------------------------------

DownloadDependency() {
  local Name=$(CheckIfNotEmpty "name" "${1:-""}")
  local Version=$(CheckIfNotEmpty "version" "${2:-""}")

  local DownloadURL="https://github.com/tomasz-walczyk/${Name}/archive/v${Version}.tar.gz"
  local ArchiveFile="${TempDir}/${Name}-v${Version}.tar.gz"
  local OutputDir="${TempDir}/${Name}-v${Version}"

  wget --quiet --output-document="${ArchiveFile}" "${DownloadURL}" \
    || Failure "Cannot download dependency: \"${DownloadURL}\""

  mkdir --parent "${OutputDir}"
  tar --extract --gzip --strip-components=1 --file "${ArchiveFile}" --directory "${OutputDir}" 
  rm "${DownloadPath}"
  echo -n "${OutputDir}"
}

#----------------------------------------------------------

ValidateSSHKeyPassword() {
  local Password=$(CheckIfNotEmpty "$@")
  if [[ ${#Password} -lt ${MinimumPasswordLength} ]]; then
    if [[ "${Password}" != "RAND" ]] && [[ "${Password}" != "READ" ]] && [[ "${Password}" != "NONE" ]]; then
      Failure "Invalid argument: \"${1}\" : Password is too short! (${MinimumPasswordLength} characters is a minimum)"
    fi
  elif [[ ${#2} -gt ${MaximumPasswordLength} ]]; then
    Failure "Invalid argument: \"${1}\" : Password is too long! (${MaximumPasswordLength} characters is a maximum)"
  fi
  echo -n "${Password}"
}

#----------------------------------------------------------

ValidateAccountPassword() {
  local Password=$(CheckIfNotEmpty "$@")
  if [[ ${#Password} -lt ${MinimumPasswordLength} ]]; then
    if [[ "${Password}" != "RAND" ]] && [[ "${Password}" != "READ" ]]; then
      Failure "Invalid argument: \"${1}\" : Password is too short! (${MinimumPasswordLength} characters is a minimum)"
    fi
  elif [[ ${#2} -gt ${MaximumPasswordLength} ]]; then
    Failure "Invalid argument: \"${1}\" : Password is too long! (${MaximumPasswordLength} characters is a maximum)"
  fi
  echo -n "${Password}"
}

#----------------------------------------------------------

ValidateHostname() {
  local Hostname=$(CheckIfNotEmpty "$@")
  local Pattern="^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$"
  (echo -n "${Hostname}" | grep --extended-regexp "${Pattern}" &> /dev/null) \
    || Failure "Invalid argument: \"${1}\" : Hostname: \"${Hostname}\" does not match pattern: \"${Pattern}\""

  echo -n "${Hostname}"
}

#----------------------------------------------------------

ValidateDomain() {
  local Domain=$(CheckIfNotEmpty "$@")
  local Pattern="^[a-zA-Z0-9][a-zA-Z0-9.-]{0,61}[a-zA-Z0-9]$"
  (echo -n "${Domain}" | grep --extended-regexp "${Pattern}" &> /dev/null) \
    || Failure "Invalid argument: \"${1}\" : Domain: \"${Domain}\" does not match pattern: \"${Pattern}\""

  echo -n "${Domain}"
}

#----------------------------------------------------------

ValidateOutputDir() {
  local Path=$(CheckIfNotEmpty "$@")
  if [[ "${Path:0:1}" != "/" ]]; then
    local Path="${PWD}/${Path}"
  fi

  if [[ -e "${Path}" ]]; then
    [[ ! -d "${Path}" ]] && Failure "Invalid argument: \"${1}\" : File \"${Path}\" already exists!"
    [[ ! -z "$(ls -A "${Path}")" ]] && Failure "Invalid argument: \"${1}\" : Directory \"${Path}\" is not empty!"
    [[ ! -w "${Path}" ]] && Failure "Invalid argument: \"${1}\" : Directory \"${Path}\" is not writable!"
  else
    [[ ! -w "$(dirname "${Path}")" ]] && Failure "Invalid argument: \"${1}\" : Directory \"$(dirname "${Path}")\" is not writable!"
  fi
  echo -n "${Path}"
}

#----------------------------------------------------------

Help() {
cat << EndOfHelp
Synopsis:
Creates unattended Debian server installer.

Description:
Script will create Debian server installer from the latest minimal CD available.
This can be changed by specifying --source-url and --iso-name-pattern arguments.
Files will be saved to the script directory unless --output-dir was specified.
All parameters are optional but missing configuration needs to provided during
server installation. Installer will use first SCSI/SATA hard disk (/dev/sda).

Usage:
${ScriptName} [OPTION]...

Options:
--ssh-key-password <string> : SSH private key password.
                            : Supported values:
                            : - RAND) : Generate random password.
                            : - READ) : Read password from standard input.
                            : - NONE) : Private key will not be encrypted.
                            : - *)    : Use argument value as a password.
                            :
--account-password <string> : Account password.
                            : Available options:
                            : - RAND) : Generate random password.
                            : - READ) : Read password from standard input.
                            : - *)    : Use argument value as a password.
                            :
--hostname         <string> : Server hostname.
--domain           <string> : Server domain.
--output-dir       <string> : Path to the output directory.
--source-url       <string> : Source URL from where ISO should be downloaded.
--iso-name-pattern <string> : Regular expression for selecting ISO file.
--boot-flags       <string> : Additional installer boot flags.
--encrypt                   : Enable full disk encryption.
--help                      : Display this help and exit.

Related links:
- https://github.com/tomasz-walczyk/create-debian-server-iso
- https://github.com/tomasz-walczyk/create-debian-iso
EndOfHelp
}

###########################################################
###                       START                         ###
###########################################################

trap Clean EXIT
trap Failure HUP INT QUIT TERM

#----------------------------------------------------------
# Parse command line arguments.
#----------------------------------------------------------

while [[ ${#} -gt 0 ]]
do
case "${1}" in
  --ssh-key-password=*) SSHKeyPassword=$(ValidateSSHKeyPassword "${1%%=*}" "${1#*=}"); shift;;
  --account-password=*) AccountPassword=$(ValidateAccountPassword "${1%%=*}" "${1#*=}"); shift;;
  --hostname=*) Hostname=$(ValidateHostname "${1%%=*}" "${1#*=}"); shift;;
  --domain=*) Domain=$(ValidateDomain "${1%%=*}" "${1#*=}"); shift;;
  --output-dir=*) OutputDir=$(ValidateOutputDir "${1%%=*}" "${1#*=}"); shift;;
  --source-url=*) SourceURL=$(CheckIfNotEmpty "${1%%=*}" "${1#*=}"); shift;;
  --iso-name-pattern=*) ISONamePattern=$(CheckIfNotEmpty "${1%%=*}" "${1#*=}"); shift;;
  --boot-flags=*) BootFlags=$(CheckIfNotEmpty "${1%%=*}" "${1#*=}"); shift;;

  --ssh-key-password) SSHKeyPassword=$(ValidateSSHKeyPassword "${1}" "${2:-""}"); shift;;
  --account-password) AccountPassword=$(ValidateAccountPassword "${1}" "${2:-""}"); shift;;
  --hostname) Hostname=$(ValidateHostname "${1}" "${2:-""}"); shift;;
  --domain) Domain=$(ValidateDomain "${1}" "${2:-""}"); shift;;
  --output-dir) OutputDir=$(ValidateOutputDir "${1}" "${2:-""}"); shift;;
  --source-url) SourceURL=$(CheckIfNotEmpty "${1}" "${2:-""}"); shift;;
  --iso-name-pattern) ISONamePattern=$(CheckIfNotEmpty "${1}" "${2:-""}"); shift;;
  --boot-flags) BootFlags=$(CheckIfNotEmpty "${1}" "${2:-""}"); shift;;

  --encrypt) Encrypt=1;;
  --help) Help; Success;;

  *=*) Failure "Unsupported argument: \"${1%%=*}\"";;
  *) Failure "Unsupported argument: \"${1}\"";;
esac
shift
done

#----------------------------------------------------------
# Check if all dependencies are installed.
#----------------------------------------------------------

MissingCommands=()
for Command in genisoimage rsync ssh-keygen mkpasswd; do
  command -v "${Command}" >/dev/null 2>&1 || MissingCommands+=("${Command}")
done

if [[  ${#MissingCommands[*]} -ne 0 ]]; then
  for Command in ${MissingCommands[*]}; do
    echo "Cannot find command: \"${Command}\"" >&2
  done
  Failure "Required commands are missing!"
fi

#----------------------------------------------------------
# Assign default values for missing arguments.
#----------------------------------------------------------

SSHKeyPassword=${SSHKeyPassword:-""}
AccountPassword=${AccountPassword:-""}
Hostname=${Hostname:-""}
Domain=${Domain:-""}
OutputDir=${OutputDir:-"${ScriptRoot}/$(date "+debian-server_%Y-%m-%d_%H-%M-%S")"}
SourceURL=${SourceURL:-""}
ISONamePattern=${ISONamePattern:-""}
BootFlags=${BootFlags:-""}
Encrypt=${Encrypt:-0}

#----------------------------------------------------------
# Download dependencies from GitHub.
#----------------------------------------------------------

CreateDebianISODir=$(DownloadDependency "create-debian-iso" "0.0.5")

#----------------------------------------------------------
# Define all needed files and directories.
#----------------------------------------------------------

readonly ServerLabel=${Hostname:-"server"}
readonly RootLabel="root@"

readonly ISOFile="${OutputDir}/${ServerLabel}.iso"
readonly PreseedFile="${OutputDir}/${ServerLabel}.seed"
readonly AttachmentDir="${OutputDir}/${ServerLabel}"
readonly AttachmentFile="${OutputDir}/${ServerLabel}.tar.gz"
readonly PasswordsFile="${OutputDir}/root@${HostLabel}.pass"
readonly PrivateKeyFile="${OutputDir}/root@${HostLabel}"
readonly PublicKeyFile="${OutputDir}/root@${HostLabel}.pub"

#----------------------------------------------------------
# Configure output directory.
#----------------------------------------------------------

# if [[ ! -e "${OutputDir}" ]]; then
#   mkdir --parents "${OutputDir}"
#   chmod 700 "${OutputDir}"
# fi

# if [[ ! -e "${AttachmentDir}" ]]; then
#   mkdir --parents "${AttachmentDir}"
#   chmod 700 "${AttachmentDir}"
# fi

mkdir --parents --mode 700 "${OutputDir}"
mkdir --parents --mode 700 "${AttachmentDir}"

#----------------------------------------------------------
# Configure full disk encryption.
#----------------------------------------------------------

if [[ "${Encrypt:-0}" -eq 0 ]]; then
  install --mode 600 "${ScriptRoot}/data/debian-server.seed" "${PreseedFile}"
else
  install --mode 600 "${ScriptRoot}/data/debian-server-crypt.seed" "${PreseedFile}"
fi

#----------------------------------------------------------
# Configure hostname.
#----------------------------------------------------------

if [[ -n "${Hostname:-""}" ]]; then
  sed --in-place "s/{{HOSTNAME}}/${Hostname}/g" "${PreseedFile}"
else
  sed --in-place "/{{HOSTNAME}}/d" "${PreseedFile}"
fi

#----------------------------------------------------------
# Configure domain.
#----------------------------------------------------------

if [[ -n "${Domain:-""}" ]]; then
  sed --in-place "s/{{DOMAIN}}/${Domain}/g" "${PreseedFile}"
else
  sed --in-place "/{{DOMAIN}}/d" "${PreseedFile}"
fi

#----------------------------------------------------------
# Configure account password.
#----------------------------------------------------------

if [[ "${AccountPassword:-""}" == "READ" ]]; then
  echo ""
  echo "+-----------------------------------------------+"
  echo "|         Account password configuration        |"
  echo "+-----------------------------------------------+"
  echo ""

  while true; do
    read -s -p "Enter password (empty for no password): " Password1 && echo ""
    read -s -p "Enter same password again: " Password2 && echo ""
    if [[ "${Password1}" != "${Password2}" ]]; then
      echo "Passwords do not match!  Try again."
    elif [[ ${#Password1} -lt ${MinimumPasswordLength} ]]; then
      echo "Password is too short! (${MinimumPasswordLength} characters is a minimum) Try again."
    elif [[ ${#Password1} -gt ${MaximumPasswordLength} ]]; then
      echo "Password is too long! (${MaximumPasswordLength} characters is a maximum) Try again."
    else
      AccountPassword=${Password1}
      unset Password1
      unset Password2
      break
    fi
  done
elif [[ "${AccountPassword}" == "RAND" ]]; then
  AccountPassword=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${RandomPasswordLength} | head -n 1) || true
  [[ -f "${PasswordsFile}" ]] && chmod 600 "${PasswordsFile}"
  echo "Login   : ${AccountPassword}" >> "${PasswordsFile}"
  chmod 400 "${PasswordsFile}"
fi

if [[ -n "${AccountPassword}" ]]; then
  PasswordHash=$(echo "${AccountPassword}" | mkpasswd --stdin --method=sha-512 --rounds=5000)
  sed --in-place "s:{{PASSWORD}}:${PasswordHash}:g" "${PreseedFile}"
else
  sed --in-place "/{{PASSWORD}}/d" "${PreseedFile}"
fi

unset AccountPassword

# Password is too short (${MinimumPasswordLength} characters is a minimum)!"
# Password is too long (${MaximumPasswordLength} characters is a maximum)!"

#----------------------------------------------------------
# Configure remote access.
#----------------------------------------------------------

if [[ "${KeyPassword}" == "READ" ]]; then
  echo ""
  echo "+-----------------------------------------------+"
  echo "|        SSH key password configuration         |"
  echo "+-----------------------------------------------+"
  echo ""

  while true; do
    if ssh-keygen -q -t ${SSHKeyType} -b ${SSHKeyBits} -f "${PrivateKeyFile}" -C "${UserLabel}@${HostLabel}" 2> /dev/null; then
      chmod 400 "${PrivateKeyFile}" "${PublicKeyFile}"
      cp "${PublicKeyFile}" ${AttachmentDir}
      break
    else
      echo "Password is too short (minimum ${MinimumPasswordLength} characters).  Try again."
    fi
  done
elif [[ -n "${KeyPassword}" ]]; then
  if [[ "${KeyPassword}" == "RAND" ]]; then
    KeyPassword=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${RandomPasswordLength} | head -n 1) || true
    [[ -f "${PasswordsFile}" ]] && chmod 600 "${PasswordsFile}"
    echo "SSH Key : ${KeyPassword}" >> "${PasswordsFile}"
    chmod 400 "${PasswordsFile}"
  elif [[ "${KeyPassword}" == "NONE" ]]; then
    KeyPassword=""
  fi

  ssh-keygen -q -t ${SSHKeyType} -b ${SSHKeyBits} -N "${KeyPassword}" -f "${PrivateKeyFile}" -C "${UserLabel}@${HostLabel}"
  chmod 400 "${PrivateKeyFile}" "${PublicKeyFile}"
  cp "${PublicKeyFile}" ${AttachmentDir}
fi

unset KeyPassword

#----------------------------------------------------------
# Configure setup script.
#----------------------------------------------------------

cp "${ScriptRoot}/data/setup.sh" "${AttachmentDir}"
chmod 500 "${AttachmentDir}/setup.sh"

#----------------------------------------------------------
# Calculate attachments checksums.
#----------------------------------------------------------

pushd "${AttachmentDir}"
sha512sum * > SHA512SUMS
chmod 400 SHA512SUMS
popd

#----------------------------------------------------------
# Create attachments archive.
#----------------------------------------------------------

pushd "${AttachmentDir}"
tar --create --gzip --file="${AttachmentFile}" *
popd

rm --recursive "${AttachmentDir}"
chmod 400 "${PreseedFile}" "${AttachmentFile}"

#----------------------------------------------------------
# Create debian server ISO.
#----------------------------------------------------------

echo ""
echo "+-----------------------------------------------+"
echo "|           Creating server installer           |"
echo "+-----------------------------------------------+"
echo ""

CreateDebianISO="bash \"${CreateDebianISODir}/create-debian-iso.bash\""
CreateDebianISO+=" --preseed-file \"${PreseedFile}\""
CreateDebianISO+=" --attachment-file \"${AttachmentFile}\""
CreateDebianISO+=" --output-file \"${ISOFile}\""
[[ -n "${SourceURL:-""}" ]] && CreateDebianISO+=" --source-url \"${SourceURL}\""
[[ -n "${ISONamePattern:-""}" ]] && CreateDebianISO+=" --iso-name-pattern \"${ISONamePattern}\""
[[ -n "${BootFlags:-""}" ]] && CreateDebianISO+=" --boot-flags \"${BootFlags}\""
eval "${CreateDebianISO}"
chmod 400 "${ISOFile}"

#----------------------------------------------------------
# Calculate output files checksums.
#----------------------------------------------------------

pushd "${OutputDir}"
sha512sum * > SHA512SUMS
chmod 400 SHA512SUMS
popd

chmod 500 "${OutputDir}"
unset DirToRemoveOnExit
