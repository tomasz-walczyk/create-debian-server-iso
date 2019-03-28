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
-k|--key-password     <string>  Root SSH key password.
                                Supported values:
                                - RAND) : Generate random password.
                                - READ) : Read password from standard input.
                                - NONE) : Private key will not be encrypted.
                                - *)    : Use argument value as a password.

-a|--account-password <string>  Root account password.
                                Available options:
                                - RAND) : Generate random password.
                                - READ) : Read password from standard input.
                                - *)    : Use argument value as a password.

-e|--encrypt                    Enable full disk encryption.
-h|--hostname         <string>  Server hostname.
-d|--domain           <string>  Server domain.
-o|--output-dir       <string>  Path to the output directory.
-s|--source-url       <string>  Source URL from where ISO should be downloaded.
-i|--iso-name-pattern <string>  Regular expression for selecting ISO file.
-b|--boot-flags       <string>  Additional installer boot flags.

   --help                       Display this help and exit.

$Related links):
- https://github.com/tomasz-walczyk/create-debian-server-iso
- https://github.com/tomasz-walczyk/create-debian-iso
EndOfHelp
}

#----------------------------------------------------------

ValidateKeyPassword() {
  [[ -z "${1+x}" ]] && Failure "Argument name is required!"
  [[ -z "${2}" ]] && Failure "Missing argument value: ${1}"

  if [[ ${#2} -gt 0 ]] && [[ ${#2} -lt ${MinimumPasswordLength} ]]; then
    if [[ "${2}" != "RAND" ]] && [[ "${2}" != "READ" ]] && [[ "${2}" != "NONE" ]]; then
      Failure "Invalid argument: ${1} : Password is too short! (minimum ${MinimumPasswordLength} characters)"
    fi
  elif [[ ${#2} -gt ${MaximumPasswordLength} ]]; then
    Failure "Invalid argument: ${1} : Password is too long! (maximum ${MaximumPasswordLength} characters)"
  fi

  echo -n "${2}"
}

#----------------------------------------------------------

ValidateAccountPassword() {
  [[ -z "${1+x}" ]] && Failure "Argument name is required!"
  [[ -z "${2}" ]] && Failure "Missing argument value: ${1}"

  if [[ ${#2} -gt 0 ]] && [[ ${#2} -lt ${MinimumPasswordLength} ]]; then
    if [[ "${2}" != "RAND" ]] && [[ "${2}" != "READ" ]]; then
      Failure "Invalid argument: ${1} : Password is too short! (minimum ${MinimumPasswordLength} characters)"
    fi
  elif [[ ${#2} -gt ${MaximumPasswordLength} ]]; then
    Failure "Invalid argument: ${1} : Password is too long! (maximum ${MaximumPasswordLength} characters)"
  fi

  echo -n "${2}"
}

#----------------------------------------------------------

ValidateHostname() {
  [[ -z "${1+x}" ]] && Failure "Argument name is required!"
  [[ -z "${2}" ]] && Failure "Missing argument value: ${1}"

  local Pattern="^[a-zA-Z0-9][a-zA-Z0-9-]{0,61}[a-zA-Z0-9]$"
  (echo -n "${2}" | grep --extended-regexp "${Pattern}" &> /dev/null) \
    || Failure "Invalid argument: ${1} : Value: \"${2}\" does not match pattern: \"${Pattern}\""

  echo -n "${2}"
}

#----------------------------------------------------------

ValidateDomain() {
  [[ -z "${1+x}" ]] && Failure "Argument name is required!"
  [[ -z "${2}" ]] && Failure "Missing argument value: ${1}"

  local Pattern="^[a-zA-Z0-9][a-zA-Z0-9.-]{0,61}[a-zA-Z0-9]$"
  (echo -n "${2}" | grep --extended-regexp "${Pattern}" &> /dev/null) \
    || Failure "Invalid argument: ${1} : Value: \"${2}\" does not match pattern: \"${Pattern}\""

  echo -n "${2}"
}

#----------------------------------------------------------

ValidateOutputDir() {
  [[ -z "${1+x}" ]] && Failure "Argument name is required!"
  [[ -z "${2}" ]] && Failure "Missing argument value: ${1}"

  if [[ "${2:0:1}" != "/" ]]; then
    local Path="${PWD}/${2}"
  else
    local Path=${2}
  fi

  if [[ -e "${Path}" ]]; then
    if [[ -d "${Path}" ]]; then
      [[ -z "$(ls -A "${Path}")" ]] || Failure "Invalid argument: ${1} : Directory \"${Path}\" is not empty!"
      [[ -w "${Path}" ]] || Failure "Invalid argument: ${1} : Directory \"${Path}\" is not writable!"
    else
      Failure "Invalid argument: ${1} : Item \"${Path}\" already exists!"
    fi
  else
    [[ -w "$(dirname "${Path}")" ]] || Failure "Invalid argument: ${1} : Directory \"$(dirname "${Path}")\" is not writable!"
  fi

  echo -n "${2}"
}

#----------------------------------------------------------

ValidateSourceURL() {
  [[ -z "${1+x}" ]] && Failure "Argument name is required!"
  [[ -z "${2}" ]] && Failure "Missing argument value: ${1}"
  echo -n "${2}"
}

#----------------------------------------------------------

ValidateISONamePattern() {
  [[ -z "${1+x}" ]] && Failure "Argument name is required!"
  [[ -z "${2}" ]] && Failure "Missing argument value: ${1}"
  echo -n "${2}"
}

#----------------------------------------------------------

ValidateBootFlags() {
  [[ -z "${1+x}" ]] && Failure "Argument name is required!"
  [[ -z "${2}" ]] && Failure "Missing argument value: ${1}"
  echo -n "${2}"
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
  -e|--encrypt) Encrypt=1;;
  -k|--key-password) KeyPassword=$(ValidateKeyPassword "${1}" "${2:-""}"); shift;;
  -a|--account-password) AccountPassword=$(ValidateAccountPassword "${1}" "${2:-""}"); shift;;
  -h|--hostname) Hostname=$(ValidateHostname "${1}" "${2:-""}"); shift;;
  -d|--domain) Domain=$(ValidateDomain "${1}" "${2:-""}"); shift;;
  -o|--output-dir) OutputDir=$(ValidateOutputDir "${1}" "${2:-""}"); shift;;
  -s|--source-url) SourceURL=$(ValidateSourceURL "${1}" "${2:-""}"); shift;;
  -i|--iso-name-pattern) ISONamePattern=$(ValidateISONamePattern "${1}" "${2:-""}"); shift;;
  -b|--boot-flags) BootFlags=$(ValidateBootFlags "${1}" "${2:-""}"); shift;;
  --help) Help; Success;;
  *) Failure "Invalid argument: \"${1}\"";;
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

Encrypt=${Encrypt:=0}
KeyPassword=${KeyPassword:=""}
AccountPassword=${AccountPassword:=""}
Username=${Username:=""}
Fullname=${Fullname:=${Username}}
Hostname=${Hostname:=""}
Domain=${Domain:=""}
OutputDir=${OutputDir:="${ScriptRoot}/$(date "+debian-server_%Y-%m-%d_%H-%M-%S")"}
SourceURL=${SourceURL:=""}
ISONamePattern=${ISONamePattern:=""}
BootFlags=${BootFlags:=""}

# #----------------------------------------------------------
# # Define all needed files and directories.
# #----------------------------------------------------------

# readonly HostLabel=${Hostname:-"server"}
# readonly UserLabel=${Username:-"root"}

# readonly ISOFile="${OutputDir}/${HostLabel}.iso"
# readonly PreseedFile="${OutputDir}/${HostLabel}.seed"
# readonly AttachmentDir="${OutputDir}/${HostLabel}"
# readonly AttachmentFile="${OutputDir}/${HostLabel}.tar.gz"
# readonly PasswordsFile="${OutputDir}/${UserLabel}@${HostLabel}.pass"
# readonly PrivateKeyFile="${OutputDir}/${UserLabel}@${HostLabel}"
# readonly PublicKeyFile="${OutputDir}/${UserLabel}@${HostLabel}.pub"

# #----------------------------------------------------------
# # Configure output directory.
# #----------------------------------------------------------

# DirToRemoveOnExit="${OutputDir}"

# if [[ ! -e "${OutputDir}" ]]; then
#   mkdir --parents "${OutputDir}"
#   chmod 700 "${OutputDir}"
# fi

# if [[ ! -e "${AttachmentDir}" ]]; then
#   mkdir --parents "${AttachmentDir}"
#   chmod 700 "${AttachmentDir}"
# fi

# #----------------------------------------------------------
# # Configure full disk encryption.
# #----------------------------------------------------------

# if [[ ${Encrypt} -eq 0 ]]; then
#   cp "${ScriptRoot}/data/debian-server.seed" "${PreseedFile}"
# else
#   cp "${ScriptRoot}/data/debian-server-crypt.seed" "${PreseedFile}"
# fi

# chmod 600 "${PreseedFile}"

# #----------------------------------------------------------
# # Configure hostname.
# #----------------------------------------------------------

# if [[ -n "${Hostname}" ]]; then
#   sed --in-place "s/{{HOSTNAME}}/${Hostname}/g" "${PreseedFile}"
# else
#   sed --in-place "/{{HOSTNAME}}/d" "${PreseedFile}"
# fi

# #----------------------------------------------------------
# # Configure domain.
# #----------------------------------------------------------

# if [[ -n "${Domain}" ]]; then
#   sed --in-place "s/{{DOMAIN}}/${Domain}/g" "${PreseedFile}"
# else
#   sed --in-place "/{{DOMAIN}}/d" "${PreseedFile}"
# fi

# #----------------------------------------------------------
# # Configure account details.
# #----------------------------------------------------------

# if [[ -n "${Username}" ]]; then
#   sed --in-place "s/{{MAKE_ROOT}}/false/g" "${PreseedFile}"
#   sed --in-place "s/{{MAKE_USER}}/true/g" "${PreseedFile}"
#   sed --in-place "s/{{USERNAME}}/${Username}/g" "${PreseedFile}"
#   sed --in-place "s/{{FULLNAME}}/${Fullname}/g" "${PreseedFile}"
#   sed --in-place "s/{{USER_PASSWORD}}/{{PASSWORD}}/g" "${PreseedFile}"
#   sed --in-place "/{{ROOT_PASSWORD}}/d" "${PreseedFile}"
# else
#   sed --in-place "s/{{MAKE_ROOT}}/true/g" "${PreseedFile}"
#   sed --in-place "s/{{MAKE_USER}}/false/g" "${PreseedFile}"
#   sed --in-place "s/{{ROOT_PASSWORD}}/{{PASSWORD}}/g" "${PreseedFile}"
#   sed --in-place "/{{USERNAME}}/d" "${PreseedFile}"
#   sed --in-place "/{{FULLNAME}}/d" "${PreseedFile}"
#   sed --in-place "/{{USER_PASSWORD}}/d" "${PreseedFile}"
# fi

# #----------------------------------------------------------
# # Configure account password.
# #----------------------------------------------------------

# if [[ "${AccountPassword}" == "READ" ]]; then
#   echo ""
#   echo "+-----------------------------------------------+"
#   echo "|         Account password configuration        |"
#   echo "+-----------------------------------------------+"
#   echo ""

#   while true; do
#     read -s -p "Enter password (empty for no password): " Password1 && echo ""
#     read -s -p "Enter same password again: " Password2 && echo ""
#     if [[ "${Password1}" != "${Password2}" ]]; then
#       echo "Passwords do not match.  Try again."
#     elif [[ ${#Password1} -gt 0 ]] && [[ ${#Password1} -lt ${MinimumPasswordLength} ]]; then
#       echo "Password is too short (minimum ${MinimumPasswordLength} characters).  Try again."
#     elif [[ ${#Password1} -gt ${MaximumPasswordLength} ]]; then
#       echo "Password is too long (maximum ${MaximumPasswordLength} characters).  Try again."
#     else
#       AccountPassword=${Password1}
#       unset Password1
#       unset Password2
#       break
#     fi
#   done
# elif [[ "${AccountPassword}" == "RAND" ]]; then
#   AccountPassword=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${RandomPasswordLength} | head -n 1) || true
#   [[ -f "${PasswordsFile}" ]] && chmod 600 "${PasswordsFile}"
#   echo "Login   : ${AccountPassword}" >> "${PasswordsFile}"
#   chmod 400 "${PasswordsFile}"
# fi

# if [[ -n "${AccountPassword}" ]]; then
#   PasswordHash=$(echo "${AccountPassword}" | mkpasswd --stdin --method=sha-512 --rounds=5000)
#   sed --in-place "s:{{PASSWORD}}:${PasswordHash}:g" "${PreseedFile}"
# else
#   sed --in-place "/{{PASSWORD}}/d" "${PreseedFile}"
# fi

# unset AccountPassword

# #----------------------------------------------------------
# # Configure remote access.
# #----------------------------------------------------------

# if [[ "${KeyPassword}" == "READ" ]]; then
#   echo ""
#   echo "+-----------------------------------------------+"
#   echo "|        SSH key password configuration         |"
#   echo "+-----------------------------------------------+"
#   echo ""

#   while true; do
#     if ssh-keygen -q -t ${SSHKeyType} -b ${SSHKeyBits} -f "${PrivateKeyFile}" -C "${UserLabel}@${HostLabel}" 2> /dev/null; then
#       chmod 400 "${PrivateKeyFile}" "${PublicKeyFile}"
#       cp "${PublicKeyFile}" ${AttachmentDir}
#       break
#     else
#       echo "Password is too short (minimum ${MinimumPasswordLength} characters).  Try again."
#     fi
#   done
# elif [[ -n "${KeyPassword}" ]]; then
#   if [[ "${KeyPassword}" == "RAND" ]]; then
#     KeyPassword=$(cat /dev/urandom | tr -dc 'a-zA-Z0-9' | fold -w ${RandomPasswordLength} | head -n 1) || true
#     [[ -f "${PasswordsFile}" ]] && chmod 600 "${PasswordsFile}"
#     echo "SSH Key : ${KeyPassword}" >> "${PasswordsFile}"
#     chmod 400 "${PasswordsFile}"
#   elif [[ "${KeyPassword}" == "NONE" ]]; then
#     KeyPassword=""
#   fi

#   ssh-keygen -q -t ${SSHKeyType} -b ${SSHKeyBits} -N "${KeyPassword}" -f "${PrivateKeyFile}" -C "${UserLabel}@${HostLabel}"
#   chmod 400 "${PrivateKeyFile}" "${PublicKeyFile}"
#   cp "${PublicKeyFile}" ${AttachmentDir}
# fi

# unset KeyPassword

# #----------------------------------------------------------
# # Configure setup script.
# #----------------------------------------------------------

# cp "${ScriptRoot}/data/setup.sh" "${AttachmentDir}"
# chmod 500 "${AttachmentDir}/setup.sh"

# #----------------------------------------------------------
# # Calculate attachments checksums.
# #----------------------------------------------------------

# pushd "${AttachmentDir}"
# sha512sum * > SHA512SUMS
# chmod 400 SHA512SUMS
# popd

# #----------------------------------------------------------
# # Create attachments archive.
# #----------------------------------------------------------

# pushd "${AttachmentDir}"
# tar --create --gzip --file="${AttachmentFile}" *
# popd

# rm --recursive "${AttachmentDir}"
# chmod 400 "${PreseedFile}" "${AttachmentFile}"

# #----------------------------------------------------------
# # Create debian server ISO.
# #----------------------------------------------------------

# echo ""
# echo "+-----------------------------------------------+"
# echo "|           Creating server installer           |"
# echo "+-----------------------------------------------+"
# echo ""

# CreateDebianISO="bash \"${ScriptRoot}/data/create-debian-iso/create-debian-iso.bash\""
# CreateDebianISO+=" --preseed-file \"${PreseedFile}\""
# CreateDebianISO+=" --attachment-file \"${AttachmentFile}\""
# CreateDebianISO+=" --output-file \"${ISOFile}\""
# [[ -n "${SourceURL}" ]] && CreateDebianISO+=" --source-url \"${SourceURL}\""
# [[ -n "${BootFlags}" ]] && CreateDebianISO+=" --boot-flags \"${BootFlags}\""
# [[ -n "${ISONamePattern}" ]] && CreateDebianISO+=" --iso-name-pattern \"${ISONamePattern}\""
# eval "${CreateDebianISO}"
# chmod 400 "${ISOFile}"

# #----------------------------------------------------------
# # Calculate output files checksums.
# #----------------------------------------------------------

# pushd "${OutputDir}"
# sha512sum * > SHA512SUMS
# chmod 400 SHA512SUMS
# popd

# chmod 500 "${OutputDir}"
# unset DirToRemoveOnExit
