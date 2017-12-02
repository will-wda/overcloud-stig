# The two fingerprints below are retrieved from https://access.redhat.com/security/team/key
readonly REDHAT_RELEASE_2_FINGERPRINT="567E 347A D004 4ADE 55BA 8A5F 199E 2F91 FD43 1D51"
readonly REDHAT_AUXILIARY_FINGERPRINT="43A6 E49C 4A38 F4BE 9ABF 2A53 4568 9C88 2FA6 58E0"
# Location of the key we would like to import (once it's integrity verified)
readonly REDHAT_RELEASE_KEY="/etc/pki/rpm-gpg/RPM-GPG-KEY-redhat-release"

RPM_GPG_DIR_PERMS=$(stat -c %a "$(dirname "$REDHAT_RELEASE_KEY")")

# Verify /etc/pki/rpm-gpg directory permissions are safe
if [ "${RPM_GPG_DIR_PERMS}" -le "755" ]
then
  # If they are safe, try to obtain fingerprints from the key file
  # (to ensure there won't be e.g. CRC error).
  IFS=$'\n' GPG_OUT=($(gpg --with-fingerprint "${REDHAT_RELEASE_KEY}" | grep 'Key fingerprint ='))
  GPG_RESULT=$?
  # No CRC error, safe to proceed
  if [ "${GPG_RESULT}" -eq "0" ]
  then
    tr -s ' ' <<< "${GPG_OUT}" | grep -vE "${REDHAT_RELEASE_2_FINGERPRINT}|${REDHAT_AUXILIARY_FINGERPRINT}" || {
      # If file doesn't contains any keys with unknown fingerprint, import it
      rpm --import "${REDHAT_RELEASE_KEY}"
    }
  fi
fi

function replace_or_append {
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  # Check sanity of the input
  if [ $# -lt "3" ]
  then
        echo "Usage: replace_or_append 'config_file_location' 'key_to_search' 'new_value'"
        echo
        echo "If symlinks need to be taken into account, add yes/no to the last argument"
        echo "to allow to 'follow_symlinks'."
        echo "Aborting."
        exit 1
  fi

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  if test -L $config_file; then
    sed_command="sed -i --follow-symlinks"
  else
    sed_command="sed -i"
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if ! [ "x$cce" = x ] && [ "$cce" != '@CCENUM@' ]; then
    cce="CCE-${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed "s/[\^=\$,;+]*//g" <<< $key)

  # If there is no print format specified in the last arg, use the default format.
  if ! [ "x$format" = x ] ; then
    printf -v formatted_output "$format" "$stripped_key" "$value"
  else
    formatted_output="$stripped_key = $value"
  fi

  # If the key exists, change it. Otherwise, add it to the config_file.
  if `grep -qi $key $config_file` ; then
    $sed_command "s/$key.*/$formatted_output/g" $config_file
  else
    # \n is precaution for case where file ends without trailing newline
    echo -e "\n# Per $cce: Set $formatted_output in $config_file" >> $config_file
    echo -e "$formatted_output" >> $config_file
  fi

}

replace_or_append '/etc/yum.conf' '^gpgcheck' '1' 'CCE-26989-4'
sed -i 's/gpgcheck=.*/gpgcheck=1/g' /etc/yum.repos.d/*
#
# Disable prelinking altogether
#
if grep -q ^PRELINKING /etc/sysconfig/prelink
then
  sed -i 's/PRELINKING.*/PRELINKING=no/g' /etc/sysconfig/prelink
else
  echo -e "\n# Set PRELINKING=no per security requirements" >> /etc/sysconfig/prelink
  echo "PRELINKING=no" >> /etc/sysconfig/prelink
fi

#
# Undo previous prelink changes to binaries
#
/usr/sbin/prelink -ua

function package_command {

# Load function arguments into local variables
local package_operation=$1
local package=$2

# Check sanity of the input
if [ $# -ne "2" ]
then
  echo "Usage: package_command 'install/uninstall' 'rpm_package_name"
  echo "Aborting."
  exit 1
fi

# If dnf is installed, use dnf; otherwise, use yum
if [ -f "/usr/bin/dnf" ] ; then
  install_util="/usr/bin/dnf"
else
  install_util="/usr/bin/yum"
fi

if [ "$package_operation" != 'remove' ] ; then
  # If the rpm is not installed, install the rpm
  if ! /bin/rpm -q --quiet $package; then
    $install_util -y $package_operation $package
  fi
else
  # If the rpm is installed, uninstall the rpm
  if /bin/rpm -q --quiet $package; then
    $install_util -y $package_operation $package
  fi
fi

}

package_command install aide
/usr/sbin/aide --init
/bin/cp -p /var/lib/aide/aide.db.new.gz /var/lib/aide/aide.db.gz
echo "05 4 * * * root /usr/sbin/aide --check" >> /etc/crontab

# Declare array to hold list of RPM packages we need to correct permissions for
declare -a SETPERMS_RPM_LIST

# Create a list of files on the system having permissions different from what
# is expected by the RPM database
FILES_WITH_INCORRECT_PERMS=($(rpm -Va --nofiledigest | grep '^.M'))

# For each file path from that list:
# * Determine the RPM package the file path is shipped by,
# * Include it into SETPERMS_RPM_LIST array

for FILE_PATH in "${FILES_WITH_INCORRECT_PERMS[@]}"
do
	RPM_PACKAGE=$(rpm -qf "$FILE_PATH")
	SETPERMS_RPM_LIST=("${SETPERMS_RPM_LIST[@]}" "$RPM_PACKAGE")
done

# Remove duplicate mention of same RPM in $SETPERMS_RPM_LIST (if any)
SETPERMS_RPM_LIST=( $(echo "${SETPERMS_RPM_LIST[@]}" | sort -n | uniq) )

# For each of the RPM packages left in the list -- reset its permissions to the
# correct values
for RPM_PACKAGE in "${SETPERMS_RPM_LIST[@]}"
do
	rpm --setperms "${RPM_PACKAGE}"
done

inactivity_timeout_value="900"

# Define constants to be reused below
ORG_GNOME_DESKTOP_SESSION="org/gnome/desktop/session"
SSG_DCONF_IDLE_DELAY_FILE="/etc/dconf/db/local.d/10-scap-security-guide"
SESSION_LOCKS_FILE="/etc/dconf/db/local.d/locks/session"
IDLE_DELAY_DEFINED="FALSE"

# First update '[org/gnome/desktop/session] idle-delay' settings in
# /etc/dconf/db/local.d/* if already defined
for FILE in /etc/dconf/db/local.d/*
do
	if grep -q -d skip "$ORG_GNOME_DESKTOP_SESSION" "$FILE"
	then
		if grep 'idle-delay' "$FILE"
		then
			sed -i "s/idle-delay=.*/idle-delay=uint32 ${inactivity_timeout_value}/g" "$FILE"
			IDLE_DELAY_DEFINED="TRUE"
		fi
	fi
done

# Then define '[org/gnome/desktop/session] idle-delay' setting
# if still not defined yet
if [ "$IDLE_DELAY_DEFINED" != "TRUE" ]
then
	echo "" >> $SSG_DCONF_IDLE_DELAY_FILE
	echo "[org/gnome/desktop/session]" >>  $SSG_DCONF_IDLE_DELAY_FILE
	echo "idle-delay=uint32 ${inactivity_timeout_value}" >> $SSG_DCONF_IDLE_DELAY_FILE
fi

# Verify if 'idle-delay' modification is locked. If not, lock it
if ! grep -q "^/${ORG_GNOME_DESKTOP_SESSION}/idle-delay$" /etc/dconf/db/local.d/locks/*
then
	# Check if "$SESSION_LOCK_FILE" exists. If not, create it.
	if [ ! -f "$SESSION_LOCKS_FILE" ]
	then
		touch "$SESSION_LOCKS_FILE"
	fi
	echo "/${ORG_GNOME_DESKTOP_SESSION}/idle-delay" >> "$SESSION_LOCKS_FILE"
fi


# Define constants to be reused below
ORG_GNOME_DESKTOP_SCREENSAVER="org/gnome/desktop/screensaver"
SSG_DCONF_IDLE_ACTIVATION_FILE="/etc/dconf/db/local.d/10-scap-security-guide"
SCREENSAVER_LOCKS_FILE="/etc/dconf/db/local.d/locks/screensaver"
IDLE_ACTIVATION_DEFINED="FALSE"

# First update '[org/gnome/desktop/screensaver] idle-activation-enabled' settings in
# /etc/dconf/db/local.d/* if already defined
for FILE in /etc/dconf/db/local.d/*
do
	if grep -q -d skip "$ORG_GNOME_DESKTOP_SCREENSAVER" "$FILE"
	then
		if grep 'idle-activation-enabled' "$FILE"
		then
			sed -i "s/idle-activation-enabled=.*/idle-activation-enabled=true/g" "$FILE"
			IDLE_ACTIVATION_DEFINED="TRUE"
		fi
	fi
done

# Then define '[org/gnome/desktop/screensaver] idle-activation-enabled' setting
# if still not defined yet
if [ "$IDLE_ACTIVATION_DEFINED" != "TRUE" ]
then
	echo "" >> $SSG_DCONF_IDLE_ACTIVATION_FILE
	echo "[org/gnome/desktop/screensaver]" >>  $SSG_DCONF_IDLE_ACTIVATION_FILE
	echo "idle-activation-enabled=true" >> $SSG_DCONF_IDLE_ACTIVATION_FILE
fi

# Verify if 'idle-activation-enabled' modification is locked. If not, lock it
if ! grep -q "^/${ORG_GNOME_DESKTOP_SCREENSAVER}/idle-activation-enabled$" /etc/dconf/db/local.d/locks/*
then
	# Check if "$SCREENSAVER_LOCK_FILE" exists. If not, create it.
	if [ ! -f "$SCREENSAVER_LOCKS_FILE" ]
	then
		touch "$SCREENSAVER_LOCKS_FILE"
	fi
	echo "/${ORG_GNOME_DESKTOP_SCREENSAVER}/idle-activation-enabled" >> "$SCREENSAVER_LOCKS_FILE"
fi


# Define constants to be reused below
ORG_GNOME_DESKTOP_SCREENSAVER="org/gnome/desktop/screensaver"
SSG_DCONF_LOCK_ENABLED_FILE="/etc/dconf/db/local.d/10-scap-security-guide"
SCREENSAVER_LOCKS_FILE="/etc/dconf/db/local.d/locks/screensaver"
LOCK_ENABLED_DEFINED="FALSE"
LOCK_DELAY_DEFINED="FALSE"

# First update '[org/gnome/desktop/screensaver] lock-enabled' and
# '[org/gnome/desktop/screensaver] lock-delay' settings in
# /etc/dconf/db/local.d/* if already defined
for FILE in /etc/dconf/db/local.d/*
do
	if grep -q -d skip "$ORG_GNOME_DESKTOP_SCREENSAVER" "$FILE"
	then
		if grep 'lock-enabled' "$FILE"
		then
			sed -i "s/lock-enabled=.*/lock-enabled=true/g" "$FILE"
			LOCK_ENABLED_DEFINED="TRUE"
		fi
		if grep 'lock-delay' "$FILE"
		then
			sed -i "s/lock-delay=.*/lock-delay=uint32 0/g" "$FILE"
			LOCK_DELAY_DEFINED="TRUE"
		fi
	fi
done

# Then define '[org/gnome/desktop/screensaver] lock-enabled' setting
# if still not defined yet
if [ "$LOCK_ENABLED_DEFINED" != "TRUE" ] || [ "$LOCK_DELAY_DEFINED" != "TRUE" ]
then
	echo "" >> $SSG_DCONF_LOCK_ENABLED_FILE
	echo "[org/gnome/desktop/screensaver]" >>  $SSG_DCONF_LOCK_ENABLED_FILE
	echo "lock-enabled=true" >> $SSG_DCONF_LOCK_ENABLED_FILE
	echo "lock-delay=uint32 0" >> $SSG_DCONF_LOCK_ENABLED_FILE
fi

# Verify if 'lock-enabled' modification is locked. If not, lock it
if ! grep -q "^/${ORG_GNOME_DESKTOP_SCREENSAVER}/lock-enabled$" /etc/dconf/db/local.d/locks/*
then
	# Check if "$SCREENSAVER_LOCK_FILE" exists. If not, create it.
	if [ ! -f "$SCREENSAVER_LOCKS_FILE" ]
	then
		touch "$SCREENSAVER_LOCKS_FILE"
	fi
	echo "/${ORG_GNOME_DESKTOP_SCREENSAVER}/lock-enabled" >> "$SCREENSAVER_LOCKS_FILE"
fi


# Verify if 'lock-delay' modification is locked. If not, lock it
if ! grep -q "^/${ORG_GNOME_DESKTOP_SCREENSAVER}/lock-delay$" /etc/dconf/db/local.d/locks/*
then
        # Check if "$SCREENSAVER_LOCK_FILE" exists. If not, create it.
        if [ ! -f "$SCREENSAVER_LOCKS_FILE" ]
        then
                touch "$SCREENSAVER_LOCKS_FILE"
        fi
        echo "/${ORG_GNOME_DESKTOP_SCREENSAVER}/lock-delay" >> "$SCREENSAVER_LOCKS_FILE"
fi

# Define constants to be reused below
ORG_GNOME_DESKTOP_SCREENSAVER="org/gnome/desktop/screensaver"
SSG_DCONF_MODE_BLANK_FILE="/etc/dconf/db/local.d/10-scap-security-guide"
SCREENSAVER_LOCKS_FILE="/etc/dconf/db/local.d/locks/screensaver"
MODE_BLANK_DEFINED="FALSE"

# First update '[org/gnome/desktop/screensaver] picture-uri' settings in
# /etc/dconf/db/local.d/* if already defined
for FILE in /etc/dconf/db/local.d/*
do
	if grep -q -d skip "$ORG_GNOME_DESKTOP_SCREENSAVER" "$FILE"
	then
		if grep 'picture-uri' "$FILE"
		then
			sed -i "s/picture-uri=.*/picture-uri=string ''/g" "$FILE"
			MODE_BLANK_DEFINED="TRUE"
		fi
	fi
done

# Then define '[org/gnome/desktop/screensaver] picture-uri' setting
# if still not defined yet
if [ "$MODE_BLANK_DEFINED" != "TRUE" ]
then
	echo "" >> $SSG_DCONF_MODE_BLANK_FILE
	echo "[org/gnome/desktop/screensaver]" >>  $SSG_DCONF_MODE_BLANK_FILE
	echo "picture-uri=string ''" >> $SSG_DCONF_MODE_BLANK_FILE
fi

# Verify if 'picture-uri' modification is locked. If not, lock it
if ! grep -q "^/${ORG_GNOME_DESKTOP_SCREENSAVER}/picture-uri$" /etc/dconf/db/local.d/locks/*
then
	# Check if "$SCREENSAVER_LOCK_FILE" exists. If not, create it.
	if [ ! -f "$SCREENSAVER_LOCKS_FILE" ]
	then
		touch "$SCREENSAVER_LOCKS_FILE"
	fi
	echo "/${ORG_GNOME_DESKTOP_SCREENSAVER}/picture-uri" >> "$SCREENSAVER_LOCKS_FILE"
fi
chown root /etc/shadow
chgrp root /etc/shadow
chmod 0000 /etc/shadow
chown root /etc/group
chgrp root /etc/group
chmod 644 /etc/group
chown root /etc/passwd
chgrp root /etc/passwd
chmod 0644 /etc/passwd
sed --follow-symlinks -i 's/\<nullok\>//g' /etc/pam.d/system-auth

if ! `grep -q ^[^#].*pam_succeed_if.*showfailed /etc/pam.d/postlogin` ; then
  if ! grep `^session.*pam_succeed_if.so /etc/pam.d/postlogin` ; then
    echo "session     [default=1]   pam_lastlog.so nowtmp showfailed" >> /etc/pam.d/postlogin
    echo "session     optional      pam_lastlog.so silent noupdate showfailed" >> /etc/pam.d/postlogin
  else
    sed -i '/^session.*pam_succeed_if.so/a session\t    optional\t  pam_lastlog.so silent noupdate showfailed' /etc/pam.d/postlogin
    sed -i '/^session.*pam_succeed_if.so/a session\t    [default=1]\t  pam_lastlog.so nowtmp showfailed' /etc/pam.d/postlogin
  fi
else
  sed -i "s/session[ ]*\[default=1][ ]*pam_lastlog.so.*/session     [default=1]   pam_lastlog.so nowtmp showfailed/g" /etc/pam.d/postlogin
  sed -i "s/session[ ]*optional[ ]*pam_lastlog.so.*/session     optional      pam_lastlog.so silent noupdate showfailed/g" /etc/pam.d/postlogin
fi
if ! grep -q "^password.*sufficient.*pam_unix.so.*sha512" /etc/pam.d/system-auth; then   
	sed -i --follow-symlinks "/^password.*sufficient.*pam_unix.so/ s/$/ sha512/" /etc/pam.d/system-auth
fi
if grep --silent ^ENCRYPT_METHOD /etc/login.defs ; then
	sed -i 's/^ENCRYPT_METHOD.*/ENCRYPT_METHOD SHA512/g' /etc/login.defs
else
	echo "" >> /etc/login.defs
	echo "ENCRYPT_METHOD SHA512" >> /etc/login.defs
fi
chown root /boot/grub2/grub.cfg
chgrp root /boot/grub2/grub.cfg


#
# Set runtime for net.ipv4.conf.default.send_redirects
#
/sbin/sysctl -q -n -w net.ipv4.conf.default.send_redirects=0

#
# If net.ipv4.conf.default.send_redirects present in /etc/sysctl.conf, change value to "0"
#	else, add "net.ipv4.conf.default.send_redirects = 0" to /etc/sysctl.conf
#

function replace_or_append {
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  # Check sanity of the input
  if [ $# -lt "3" ]
  then
        echo "Usage: replace_or_append 'config_file_location' 'key_to_search' 'new_value'"
        echo
        echo "If symlinks need to be taken into account, add yes/no to the last argument"
        echo "to allow to 'follow_symlinks'."
        echo "Aborting."
        exit 1
  fi

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  if test -L $config_file; then
    sed_command="sed -i --follow-symlinks"
  else
    sed_command="sed -i"
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if ! [ "x$cce" = x ] && [ "$cce" != '@CCENUM@' ]; then
    cce="CCE-${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed "s/[\^=\$,;+]*//g" <<< $key)

  # If there is no print format specified in the last arg, use the default format.
  if ! [ "x$format" = x ] ; then
    printf -v formatted_output "$format" "$stripped_key" "$value"
  else
    formatted_output="$stripped_key = $value"
  fi

  # If the key exists, change it. Otherwise, add it to the config_file.
  if `grep -qi $key $config_file` ; then
    $sed_command "s/$key.*/$formatted_output/g" $config_file
  else
    # \n is precaution for case where file ends without trailing newline
    echo -e "\n# Per $cce: Set $formatted_output in $config_file" >> $config_file
    echo -e "$formatted_output" >> $config_file
  fi

}

replace_or_append '/etc/sysctl.conf' '^net.ipv4.conf.default.send_redirects' "0" 'CCE-80156-3'


#
# Set runtime for net.ipv4.conf.all.send_redirects
#
/sbin/sysctl -q -n -w net.ipv4.conf.all.send_redirects=0

#
# If net.ipv4.conf.all.send_redirects present in /etc/sysctl.conf, change value to "0"
#	else, add "net.ipv4.conf.all.send_redirects = 0" to /etc/sysctl.conf
#

function replace_or_append {
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  # Check sanity of the input
  if [ $# -lt "3" ]
  then
        echo "Usage: replace_or_append 'config_file_location' 'key_to_search' 'new_value'"
        echo
        echo "If symlinks need to be taken into account, add yes/no to the last argument"
        echo "to allow to 'follow_symlinks'."
        echo "Aborting."
        exit 1
  fi

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  if test -L $config_file; then
    sed_command="sed -i --follow-symlinks"
  else
    sed_command="sed -i"
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if ! [ "x$cce" = x ] && [ "$cce" != '@CCENUM@' ]; then
    cce="CCE-${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed "s/[\^=\$,;+]*//g" <<< $key)

  # If there is no print format specified in the last arg, use the default format.
  if ! [ "x$format" = x ] ; then
    printf -v formatted_output "$format" "$stripped_key" "$value"
  else
    formatted_output="$stripped_key = $value"
  fi

  # If the key exists, change it. Otherwise, add it to the config_file.
  if `grep -qi $key $config_file` ; then
    $sed_command "s/$key.*/$formatted_output/g" $config_file
  else
    # \n is precaution for case where file ends without trailing newline
    echo -e "\n# Per $cce: Set $formatted_output in $config_file" >> $config_file
    echo -e "$formatted_output" >> $config_file
  fi

}

replace_or_append '/etc/sysctl.conf' '^net.ipv4.conf.all.send_redirects' "0" 'CCE-80156-3'

sysctl_net_ipv4_conf_all_accept_redirects_value="0"

#
# Set runtime for net.ipv4.conf.all.accept_redirects
#
/sbin/sysctl -q -n -w net.ipv4.conf.all.accept_redirects=$sysctl_net_ipv4_conf_all_accept_redirects_value

#
# If net.ipv4.conf.all.accept_redirects present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.all.accept_redirects = value" to /etc/sysctl.conf
#

function replace_or_append {
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  # Check sanity of the input
  if [ $# -lt "3" ]
  then
        echo "Usage: replace_or_append 'config_file_location' 'key_to_search' 'new_value'"
        echo
        echo "If symlinks need to be taken into account, add yes/no to the last argument"
        echo "to allow to 'follow_symlinks'."
        echo "Aborting."
        exit 1
  fi

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  if test -L $config_file; then
    sed_command="sed -i --follow-symlinks"
  else
    sed_command="sed -i"
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if ! [ "x$cce" = x ] && [ "$cce" != '@CCENUM@' ]; then
    cce="CCE-${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed "s/[\^=\$,;+]*//g" <<< $key)

  # If there is no print format specified in the last arg, use the default format.
  if ! [ "x$format" = x ] ; then
    printf -v formatted_output "$format" "$stripped_key" "$value"
  else
    formatted_output="$stripped_key = $value"
  fi

  # If the key exists, change it. Otherwise, add it to the config_file.
  if `grep -qi $key $config_file` ; then
    $sed_command "s/$key.*/$formatted_output/g" $config_file
  else
    # \n is precaution for case where file ends without trailing newline
    echo -e "\n# Per $cce: Set $formatted_output in $config_file" >> $config_file
    echo -e "$formatted_output" >> $config_file
  fi

}

replace_or_append '/etc/sysctl.conf' '^net.ipv4.conf.all.accept_redirects' "$sysctl_net_ipv4_conf_all_accept_redirects_value" 'CCE-80158-9'

sysctl_net_ipv4_conf_default_accept_source_route_value="0"

#
# Set runtime for net.ipv4.conf.default.accept_source_route
#
/sbin/sysctl -q -n -w net.ipv4.conf.default.accept_source_route=$sysctl_net_ipv4_conf_default_accept_source_route_value

#
# If net.ipv4.conf.default.accept_source_route present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.default.accept_source_route = value" to /etc/sysctl.conf
#

function replace_or_append {
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  # Check sanity of the input
  if [ $# -lt "3" ]
  then
        echo "Usage: replace_or_append 'config_file_location' 'key_to_search' 'new_value'"
        echo
        echo "If symlinks need to be taken into account, add yes/no to the last argument"
        echo "to allow to 'follow_symlinks'."
        echo "Aborting."
        exit 1
  fi

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  if test -L $config_file; then
    sed_command="sed -i --follow-symlinks"
  else
    sed_command="sed -i"
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if ! [ "x$cce" = x ] && [ "$cce" != '@CCENUM@' ]; then
    cce="CCE-${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed "s/[\^=\$,;+]*//g" <<< $key)

  # If there is no print format specified in the last arg, use the default format.
  if ! [ "x$format" = x ] ; then
    printf -v formatted_output "$format" "$stripped_key" "$value"
  else
    formatted_output="$stripped_key = $value"
  fi

  # If the key exists, change it. Otherwise, add it to the config_file.
  if `grep -qi $key $config_file` ; then
    $sed_command "s/$key.*/$formatted_output/g" $config_file
  else
    # \n is precaution for case where file ends without trailing newline
    echo -e "\n# Per $cce: Set $formatted_output in $config_file" >> $config_file
    echo -e "$formatted_output" >> $config_file
  fi

}

replace_or_append '/etc/sysctl.conf' '^net.ipv4.conf.default.accept_source_route' "$sysctl_net_ipv4_conf_default_accept_source_route_value" 'CCE-80162-1'

sysctl_net_ipv4_conf_default_accept_redirects_value="0"

#
# Set runtime for net.ipv4.conf.default.accept_redirects
#
/sbin/sysctl -q -n -w net.ipv4.conf.default.accept_redirects=$sysctl_net_ipv4_conf_default_accept_redirects_value

#
# If net.ipv4.conf.default.accept_redirects present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.default.accept_redirects = value" to /etc/sysctl.conf
#

function replace_or_append {
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  # Check sanity of the input
  if [ $# -lt "3" ]
  then
        echo "Usage: replace_or_append 'config_file_location' 'key_to_search' 'new_value'"
        echo
        echo "If symlinks need to be taken into account, add yes/no to the last argument"
        echo "to allow to 'follow_symlinks'."
        echo "Aborting."
        exit 1
  fi

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  if test -L $config_file; then
    sed_command="sed -i --follow-symlinks"
  else
    sed_command="sed -i"
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if ! [ "x$cce" = x ] && [ "$cce" != '@CCENUM@' ]; then
    cce="CCE-${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed "s/[\^=\$,;+]*//g" <<< $key)

  # If there is no print format specified in the last arg, use the default format.
  if ! [ "x$format" = x ] ; then
    printf -v formatted_output "$format" "$stripped_key" "$value"
  else
    formatted_output="$stripped_key = $value"
  fi

  # If the key exists, change it. Otherwise, add it to the config_file.
  if `grep -qi $key $config_file` ; then
    $sed_command "s/$key.*/$formatted_output/g" $config_file
  else
    # \n is precaution for case where file ends without trailing newline
    echo -e "\n# Per $cce: Set $formatted_output in $config_file" >> $config_file
    echo -e "$formatted_output" >> $config_file
  fi

}

replace_or_append '/etc/sysctl.conf' '^net.ipv4.conf.default.accept_redirects' "$sysctl_net_ipv4_conf_default_accept_redirects_value" 'CCE-80163-9'

sysctl_net_ipv4_icmp_echo_ignore_broadcasts_value="1"

#
# Set runtime for net.ipv4.icmp_echo_ignore_broadcasts
#
/sbin/sysctl -q -n -w net.ipv4.icmp_echo_ignore_broadcasts=$sysctl_net_ipv4_icmp_echo_ignore_broadcasts_value

#
# If net.ipv4.icmp_echo_ignore_broadcasts present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.icmp_echo_ignore_broadcasts = value" to /etc/sysctl.conf
#

function replace_or_append {
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  # Check sanity of the input
  if [ $# -lt "3" ]
  then
        echo "Usage: replace_or_append 'config_file_location' 'key_to_search' 'new_value'"
        echo
        echo "If symlinks need to be taken into account, add yes/no to the last argument"
        echo "to allow to 'follow_symlinks'."
        echo "Aborting."
        exit 1
  fi

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  if test -L $config_file; then
    sed_command="sed -i --follow-symlinks"
  else
    sed_command="sed -i"
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if ! [ "x$cce" = x ] && [ "$cce" != '@CCENUM@' ]; then
    cce="CCE-${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed "s/[\^=\$,;+]*//g" <<< $key)

  # If there is no print format specified in the last arg, use the default format.
  if ! [ "x$format" = x ] ; then
    printf -v formatted_output "$format" "$stripped_key" "$value"
  else
    formatted_output="$stripped_key = $value"
  fi

  # If the key exists, change it. Otherwise, add it to the config_file.
  if `grep -qi $key $config_file` ; then
    $sed_command "s/$key.*/$formatted_output/g" $config_file
  else
    # \n is precaution for case where file ends without trailing newline
    echo -e "\n# Per $cce: Set $formatted_output in $config_file" >> $config_file
    echo -e "$formatted_output" >> $config_file
  fi

}

replace_or_append '/etc/sysctl.conf' '^net.ipv4.icmp_echo_ignore_broadcasts' "$sysctl_net_ipv4_icmp_echo_ignore_broadcasts_value" 'CCE-80165-4'

sysctl_net_ipv4_tcp_syncookies_value="1"

#
# Set runtime for net.ipv4.tcp_syncookies
#
/sbin/sysctl -q -n -w net.ipv4.tcp_syncookies=$sysctl_net_ipv4_tcp_syncookies_value

#
# If net.ipv4.tcp_syncookies present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.tcp_syncookies = value" to /etc/sysctl.conf
#

function replace_or_append {
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  # Check sanity of the input
  if [ $# -lt "3" ]
  then
        echo "Usage: replace_or_append 'config_file_location' 'key_to_search' 'new_value'"
        echo
        echo "If symlinks need to be taken into account, add yes/no to the last argument"
        echo "to allow to 'follow_symlinks'."
        echo "Aborting."
        exit 1
  fi

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  if test -L $config_file; then
    sed_command="sed -i --follow-symlinks"
  else
    sed_command="sed -i"
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if ! [ "x$cce" = x ] && [ "$cce" != '@CCENUM@' ]; then
    cce="CCE-${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed "s/[\^=\$,;+]*//g" <<< $key)

  # If there is no print format specified in the last arg, use the default format.
  if ! [ "x$format" = x ] ; then
    printf -v formatted_output "$format" "$stripped_key" "$value"
  else
    formatted_output="$stripped_key = $value"
  fi

  # If the key exists, change it. Otherwise, add it to the config_file.
  if `grep -qi $key $config_file` ; then
    $sed_command "s/$key.*/$formatted_output/g" $config_file
  else
    # \n is precaution for case where file ends without trailing newline
    echo -e "\n# Per $cce: Set $formatted_output in $config_file" >> $config_file
    echo -e "$formatted_output" >> $config_file
  fi

}

replace_or_append '/etc/sysctl.conf' '^net.ipv4.tcp_syncookies' "$sysctl_net_ipv4_tcp_syncookies_value" 'CCE-27495-1'
if grep --silent "^install bluetooth" /etc/modprobe.d/bluetooth.conf ; then
        sed -i 's/^install bluetooth.*/install bluetooth /bin/true/g' /etc/modprobe.d/bluetooth.conf
else
        echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/bluetooth.conf
        echo "install bluetooth /bin/true" >> /etc/modprobe.d/bluetooth.conf
fi

function service_command {

# Load function arguments into local variables
local service_state=$1
local service=$2
local xinetd=$(echo $3 | cut -d'=' -f2)

# Check sanity of the input
if [ $# -lt "2" ]
then
  echo "Usage: service_command 'enable/disable' 'service_name.service'"
  echo
  echo "To enable or disable xinetd services add \'xinetd=service_name\'"
  echo "as the last argument"
  echo "Aborting."
  exit 1
fi

# If systemctl is installed, use systemctl command; otherwise, use the service/chkconfig commands
if [ -f "/usr/bin/systemctl" ] ; then
  service_util="/usr/bin/systemctl"
else
  service_util="/sbin/service"
  chkconfig_util="/sbin/chkconfig"
fi

# If disable is not specified in arg1, set variables to enable services.
# Otherwise, variables are to be set to disable services.
if [ "$service_state" != 'disable' ] ; then
  service_state="enable"
  service_operation="start"
  chkconfig_state="on"
else
  service_state="disable"
  service_operation="stop"
  chkconfig_state="off"
fi

# If chkconfig_util is not empty, use chkconfig/service commands.
if ! [ "x$chkconfig_util" = x ] ; then
  $service_util $service $service_operation
  $chkconfig_util --level 0123456 $service $chkconfig_state
else
  $service_util $service_operation $service
  $service_util $service_state $service
fi

# Test if local variable xinetd is empty using non-bashism.
# If empty, then xinetd is not being used.
if ! [ "x$xinetd" = x ] ; then
  grep -qi disable /etc/xinetd.d/$xinetd && \

  if ! [ "$service_operation" != 'disable' ] ; then
    sed -i "s/disable.*/disable         = no/gI" /etc/xinetd.d/$xinetd
  else
    sed -i "s/disable.*/disable         = yes/gI" /etc/xinetd.d/$xinetd
  fi
fi

}

service_command disable firewalld
if grep --silent "^install dccp" /etc/modprobe.d/dccp.conf ; then
        sed -i 's/^install dccp.*/install dccp /bin/true/g' /etc/modprobe.d/dccp.conf
else
        echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/dccp.conf
        echo "install dccp /bin/true" >> /etc/modprobe.d/dccp.conf
fi
if grep --silent "^install sctp" /etc/modprobe.d/sctp.conf ; then
        sed -i 's/^install sctp.*/install sctp /bin/true/g' /etc/modprobe.d/sctp.conf
else
        echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/sctp.conf
        echo "install sctp /bin/true" >> /etc/modprobe.d/sctp.conf
fi

function service_command {

# Load function arguments into local variables
local service_state=$1
local service=$2
local xinetd=$(echo $3 | cut -d'=' -f2)

# Check sanity of the input
if [ $# -lt "2" ]
then
  echo "Usage: service_command 'enable/disable' 'service_name.service'"
  echo
  echo "To enable or disable xinetd services add \'xinetd=service_name\'"
  echo "as the last argument"
  echo "Aborting."
  exit 1
fi

# If systemctl is installed, use systemctl command; otherwise, use the service/chkconfig commands
if [ -f "/usr/bin/systemctl" ] ; then
  service_util="/usr/bin/systemctl"
else
  service_util="/sbin/service"
  chkconfig_util="/sbin/chkconfig"
fi

# If disable is not specified in arg1, set variables to enable services.
# Otherwise, variables are to be set to disable services.
if [ "$service_state" != 'disable' ] ; then
  service_state="enable"
  service_operation="start"
  chkconfig_state="on"
else
  service_state="disable"
  service_operation="stop"
  chkconfig_state="off"
fi

# If chkconfig_util is not empty, use chkconfig/service commands.
if ! [ "x$chkconfig_util" = x ] ; then
  $service_util $service $service_operation
  $chkconfig_util --level 0123456 $service $chkconfig_state
else
  $service_util $service_operation $service
  $service_util $service_state $service
fi

# Test if local variable xinetd is empty using non-bashism.
# If empty, then xinetd is not being used.
if ! [ "x$xinetd" = x ] ; then
  grep -qi disable /etc/xinetd.d/$xinetd && \

  if ! [ "$service_operation" != 'disable' ] ; then
    sed -i "s/disable.*/disable         = no/gI" /etc/xinetd.d/$xinetd
  else
    sed -i "s/disable.*/disable         = yes/gI" /etc/xinetd.d/$xinetd
  fi
fi

}

service_command enable auditd

# Correct the form of default kernel command line in /etc/default/grub
grep -q ^GRUB_CMDLINE_LINUX=\".*audit=0.*\" /etc/default/grub && \
  sed -i "s/audit=[^[:space:]\+]/audit=1/g" /etc/default/grub
if ! [ $? -eq 0 ]; then
  sed -i "s/\(GRUB_CMDLINE_LINUX=\)\"\(.*\)\"/\1\"\2 audit=1\"/" /etc/default/grub
fi

# Correct the form of kernel command line for each installed kernel
# in the bootloader
/sbin/grubby --update-kernel=ALL --args="audit=1"

var_auditd_num_logs="5"

AUDITCONFIG=/etc/audit/auditd.conf

grep -q ^num_logs $AUDITCONFIG && \
  sed -i 's/^num_logs.*/num_logs = '"$var_auditd_num_logs"'/g' $AUDITCONFIG
if ! [ $? -eq 0 ]; then
  echo "num_logs = $var_auditd_num_logs" >> $AUDITCONFIG
fi

var_auditd_max_log_file="6"

AUDITCONFIG=/etc/audit/auditd.conf

grep -q ^max_log_file $AUDITCONFIG && \
  sed -i 's/^max_log_file.*/max_log_file = '"$var_auditd_max_log_file"'/g' $AUDITCONFIG
if ! [ $? -eq 0 ]; then
  echo "max_log_file = $var_auditd_max_log_file" >> $AUDITCONFIG
fi

var_auditd_max_log_file_action="rotate"

AUDITCONFIG=/etc/audit/auditd.conf

grep -q ^max_log_file_action $AUDITCONFIG && \
  sed -i 's/^max_log_file_action.*/max_log_file_action = '"$var_auditd_max_log_file_action"'/g' $AUDITCONFIG
if ! [ $? -eq 0 ]; then
  echo "max_log_file_action = $var_auditd_max_log_file_action" >> $AUDITCONFIG
fi

var_auditd_space_left_action="email"

grep -q ^space_left_action /etc/audit/auditd.conf && \
  sed -i "s/space_left_action.*/space_left_action = $var_auditd_space_left_action/g" /etc/audit/auditd.conf
if ! [ $? -eq 0 ]; then
    echo "space_left_action = $var_auditd_space_left_action" >> /etc/audit/auditd.conf
fi

var_auditd_admin_space_left_action="single"

grep -q ^admin_space_left_action /etc/audit/auditd.conf && \
  sed -i "s/admin_space_left_action.*/admin_space_left_action = $var_auditd_admin_space_left_action/g" /etc/audit/auditd.conf
if ! [ $? -eq 0 ]; then
    echo "admin_space_left_action = $var_auditd_admin_space_left_action" >> /etc/audit/auditd.conf
fi

var_auditd_action_mail_acct="root"

AUDITCONFIG=/etc/audit/auditd.conf

grep -q ^action_mail_acct $AUDITCONFIG && \
  sed -i 's/^action_mail_acct.*/action_mail_acct = '"$var_auditd_action_mail_acct"'/g' $AUDITCONFIG
if ! [ $? -eq 0 ]; then
  echo "action_mail_acct = $var_auditd_action_mail_acct" >> $AUDITCONFIG
fi

grep -q ^active /etc/audisp/plugins.d/syslog.conf && \
  sed -i "s/active.*/active = yes/g" /etc/audisp/plugins.d/syslog.conf
if ! [ $? -eq 0 ]; then
    echo "active = yes" >> /etc/audisp/plugins.d/syslog.conf
fi

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

function rhel7_fedora_perform_audit_adjtimex_settimeofday_stime_remediation {

# Perform the remediation for the 'adjtimex', 'settimeofday', and 'stime' audit
# system calls on Red Hat Enterprise Linux 7 or Fedora OSes
#
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do

        PATTERN="-a always,exit -F arch=${ARCH} -S .* -k *"
        # Create expected audit group and audit rule form for particular system call & architecture
        if [ ${ARCH} = "b32" ]
        then
                # stime system call is known at 32-bit arch (see e.g "$ ausyscall i386 stime" 's output)
                # so append it to the list of time group system calls to be audited
                GROUP="\(adjtimex\|settimeofday\|stime\)"
                FULL_RULE="-a always,exit -F arch=${ARCH} -S adjtimex -S settimeofday -S stime -k audit_time_rules"
        elif [ ${ARCH} = "b64" ]
        then
                # stime system call isn't known at 64-bit arch (see "$ ausyscall x86_64 stime" 's output)
                # therefore don't add it to the list of time group system calls to be audited
                GROUP="\(adjtimex\|settimeofday\)"
                FULL_RULE="-a always,exit -F arch=${ARCH} -S adjtimex -S settimeofday -k audit_time_rules"
        fi
        # Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
        fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
        fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done

}

rhel7_fedora_perform_audit_adjtimex_settimeofday_stime_remediation

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

function rhel7_fedora_perform_audit_adjtimex_settimeofday_stime_remediation {

# Perform the remediation for the 'adjtimex', 'settimeofday', and 'stime' audit
# system calls on Red Hat Enterprise Linux 7 or Fedora OSes
#
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do

        PATTERN="-a always,exit -F arch=${ARCH} -S .* -k *"
        # Create expected audit group and audit rule form for particular system call & architecture
        if [ ${ARCH} = "b32" ]
        then
                # stime system call is known at 32-bit arch (see e.g "$ ausyscall i386 stime" 's output)
                # so append it to the list of time group system calls to be audited
                GROUP="\(adjtimex\|settimeofday\|stime\)"
                FULL_RULE="-a always,exit -F arch=${ARCH} -S adjtimex -S settimeofday -S stime -k audit_time_rules"
        elif [ ${ARCH} = "b64" ]
        then
                # stime system call isn't known at 64-bit arch (see "$ ausyscall x86_64 stime" 's output)
                # therefore don't add it to the list of time group system calls to be audited
                GROUP="\(adjtimex\|settimeofday\)"
                FULL_RULE="-a always,exit -F arch=${ARCH} -S adjtimex -S settimeofday -k audit_time_rules"
        fi
        # Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
        fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
        fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done

}

rhel7_fedora_perform_audit_adjtimex_settimeofday_stime_remediation

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
# 
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

function rhel7_fedora_perform_audit_adjtimex_settimeofday_stime_remediation {

# Perform the remediation for the 'adjtimex', 'settimeofday', and 'stime' audit
# system calls on Red Hat Enterprise Linux 7 or Fedora OSes
#
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do

        PATTERN="-a always,exit -F arch=${ARCH} -S .* -k *"
        # Create expected audit group and audit rule form for particular system call & architecture
        if [ ${ARCH} = "b32" ]
        then
                # stime system call is known at 32-bit arch (see e.g "$ ausyscall i386 stime" 's output)
                # so append it to the list of time group system calls to be audited
                GROUP="\(adjtimex\|settimeofday\|stime\)"
                FULL_RULE="-a always,exit -F arch=${ARCH} -S adjtimex -S settimeofday -S stime -k audit_time_rules"
        elif [ ${ARCH} = "b64" ]
        then
                # stime system call isn't known at 64-bit arch (see "$ ausyscall x86_64 stime" 's output)
                # therefore don't add it to the list of time group system calls to be audited
                GROUP="\(adjtimex\|settimeofday\)"
                FULL_RULE="-a always,exit -F arch=${ARCH} -S adjtimex -S settimeofday -k audit_time_rules"
        fi
        # Perform the remediation for both possible tools: 'auditctl' and 'augenrules'
        fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
        fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done

}

rhel7_fedora_perform_audit_adjtimex_settimeofday_stime_remediation


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S clock_settime -F a0=.* \(-F key=\|-k \).*"
	GROUP="clock_settime"
	FULL_RULE="-a always,exit -F arch=$ARCH -S clock_settime -F a0=0x0 -k time-change"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done


# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/localtime" "wa" "audit_time_rules"
fix_audit_watch_rule "augenrules" "/etc/localtime" "wa" "audit_time_rules"


# Perform the remediation
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/group" "wa" "audit_rules_usergroup_modification"
fix_audit_watch_rule "augenrules" "/etc/group" "wa" "audit_rules_usergroup_modification"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/passwd" "wa" "audit_rules_usergroup_modification"
fix_audit_watch_rule "augenrules" "/etc/passwd" "wa" "audit_rules_usergroup_modification"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/gshadow" "wa" "audit_rules_usergroup_modification"
fix_audit_watch_rule "augenrules" "/etc/gshadow" "wa" "audit_rules_usergroup_modification"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/shadow" "wa" "audit_rules_usergroup_modification"
fix_audit_watch_rule "augenrules" "/etc/shadow" "wa" "audit_rules_usergroup_modification"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/security/opasswd" "wa" "audit_rules_usergroup_modification"
fix_audit_watch_rule "augenrules" "/etc/security/opasswd" "wa" "audit_rules_usergroup_modification"


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S .* -k *"
	# Use escaped BRE regex to specify rule group
	GROUP="set\(host\|domain\)name"
	FULL_RULE="-a always,exit -F arch=$ARCH -S sethostname -S setdomainname -k audit_rules_networkconfig_modification"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done

# Then perform the remediations for the watch rules
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/issue" "wa" "audit_rules_networkconfig_modification"
fix_audit_watch_rule "augenrules" "/etc/issue" "wa" "audit_rules_networkconfig_modification"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/issue.net" "wa" "audit_rules_networkconfig_modification"
fix_audit_watch_rule "augenrules" "/etc/issue.net" "wa" "audit_rules_networkconfig_modification"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/hosts" "wa" "audit_rules_networkconfig_modification"
fix_audit_watch_rule "augenrules" "/etc/hosts" "wa" "audit_rules_networkconfig_modification"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/sysconfig/network" "wa" "audit_rules_networkconfig_modification"
fix_audit_watch_rule "augenrules" "/etc/sysconfig/network" "wa" "audit_rules_networkconfig_modification"

if `grep -q ^log_group /etc/audit/auditd.conf` ; then
  GROUP=$(awk -F "=" '/log_group/ {print $2}' /etc/audit/auditd.conf | tr -d ' ')
  if ! [ "${GROUP}" == 'root' ] ; then
    chmod 0640 /var/log/audit/audit.log
    chmod 0440 /var/log/audit/audit.log.*
  else
    chmod 0600 /var/log/audit/audit.log
    chmod 0400 /var/log/audit/audit.log.*
  fi

  chmod 0640 /etc/audit/audit*
  chmod 0640 /etc/audit/rules.d/*
else
  chmod 0600 /var/log/audit/audit.log
  chmod 0400 /var/log/audit/audit.log.*
  chmod 0640 /etc/audit/audit*
  chmod 0640 /etc/audit/rules.d/*
fi

if `grep -q ^log_group /etc/audit/auditd.conf` ; then
  GROUP=$(awk -F "=" '/log_group/ {print $2}' /etc/audit/auditd.conf | tr -d ' ')
  if ! [ "${GROUP}" == 'root' ] ; then
    chown root.${GROUP} /var/log/audit
    chown root.${GROUP} /var/log/audit/audit.log*
  else
    chown root.root /var/log/audit
    chown root.root /var/log/audit/audit.log*
  fi
else
  chown root.root /var/log/audit
  chown root.root /var/log/audit/audit.log*
fi


# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/selinux/" "wa" "MAC-policy"
fix_audit_watch_rule "augenrules" "/etc/selinux/" "wa" "MAC-policy"


# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="chmod"
	FULL_RULE="-a always,exit -F arch=$ARCH -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done


# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=${ARCH} -S .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="chown"
	FULL_RULE="-a always,exit -F arch=${ARCH} -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done


# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="chmod"
	FULL_RULE="-a always,exit -F arch=$ARCH -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done


# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="chmod"
	FULL_RULE="-a always,exit -F arch=$ARCH -S chmod -S fchmod -S fchmodat -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done


# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=${ARCH} -S .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="chown"
	FULL_RULE="-a always,exit -F arch=${ARCH} -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done


# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=${ARCH} -S .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="chown"
	FULL_RULE="-a always,exit -F arch=${ARCH} -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done


# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="xattr"
	FULL_RULE="-a always,exit -F arch=${ARCH} -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done


# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="xattr"
	FULL_RULE="-a always,exit -F arch=${ARCH} -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done


# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=${ARCH} -S .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="chown"
	FULL_RULE="-a always,exit -F arch=${ARCH} -S chown -S fchown -S fchownat -S lchown -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done


# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="xattr"
	FULL_RULE="-a always,exit -F arch=${ARCH} -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done


# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="xattr"
	FULL_RULE="-a always,exit -F arch=${ARCH} -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done


# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="xattr"
	FULL_RULE="-a always,exit -F arch=${ARCH} -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done


# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="xattr"
	FULL_RULE="-a always,exit -F arch=${ARCH} -S setxattr -S lsetxattr -S fsetxattr -S removexattr -S lremovexattr -S fremovexattr -F auid>=1000 -F auid!=4294967295 -k perm_mod"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done


# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/var/log/tallylog" "wa" "logins"
fix_audit_watch_rule "augenrules" "/var/log/tallylog" "wa" "logins"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/var/run/faillock/" "wa" "logins"
fix_audit_watch_rule "augenrules" "/var/run/faillock/" "wa" "logins"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/var/log/lastlog" "wa" "logins"
fix_audit_watch_rule "augenrules" "/var/log/lastlog" "wa" "logins"


# Perform the remediation
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/var/run/utmp" "wa" "session"
fix_audit_watch_rule "augenrules" "/var/run/utmp" "wa" "session"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/var/log/btmp" "wa" "session"
fix_audit_watch_rule "augenrules" "/var/log/btmp" "wa" "session"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/var/log/wtmp" "wa" "session"
fix_audit_watch_rule "augenrules" "/var/log/wtmp" "wa" "session"


# Perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do

	# First fix the -EACCES requirement
	PATTERN="-a always,exit -F arch=$ARCH -S .* -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k *"
	# Use escaped BRE regex to specify rule group
	GROUP="\(creat\|open\|truncate\)"
	FULL_RULE="-a always,exit -F arch=$ARCH -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EACCES -F auid>=1000 -F auid!=4294967295 -k access"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"

	# Then fix the -EPERM requirement
	PATTERN="-a always,exit -F arch=$ARCH -S .* -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k *"
	# No need to change content of $GROUP variable - it's the same as for -EACCES case above
	FULL_RULE="-a always,exit -F arch=$ARCH -S creat -S open -S openat -S open_by_handle_at -S truncate -S ftruncate -F exit=-EPERM -F auid>=1000 -F auid!=4294967295 -k access"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"

done


# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function perform_audit_rules_privileged_commands_remediation {
#
# Load function arguments into local variables
local tool="$1"
local min_auid="$2"

# Check sanity of the input
if [ $# -ne "2" ]
then
        echo "Usage: perform_audit_rules_privileged_commands_remediation 'auditctl | augenrules' '500 | 1000'"
        echo "Aborting."
        exit 1
fi

declare -a files_to_inspect=()

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then:
# * add '/etc/audit/audit.rules'to the list of files to be inspected,
# * specify '/etc/audit/audit.rules' as the output audit file, where
#   missing rules should be inserted
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("/etc/audit/audit.rules")
        output_audit_file="/etc/audit/audit.rules"
#
# If the audit tool is 'augenrules', then:
# * add '/etc/audit/rules.d/*.rules' to the list of files to be inspected
#   (split by newline),
# * specify /etc/audit/rules.d/privileged.rules' as the output file, where
#   missing rules should be inserted
elif [ "$tool" == 'augenrules' ]
then
        IFS=$'\n' files_to_inspect=($(find /etc/audit/rules.d -maxdepth 1 -type f -name *.rules -print))
        output_audit_file="/etc/audit/rules.d/privileged.rules"
fi

# Obtain the list of SUID/SGID binaries on the particular system (split by newline)
# into privileged_binaries array
IFS=$'\n' privileged_binaries=($(find / -xdev -type f -perm -4000 -o -type f -perm -2000 2>/dev/null))

# Keep list of SUID/SGID binaries that have been already handled within some previous iteration
declare -a sbinaries_to_skip=()

# For each found sbinary in privileged_binaries list
for sbinary in "${privileged_binaries[@]}"
do

        # Replace possible slash '/' character in sbinary definition so we could use it in sed expressions below
        sbinary_esc=${sbinary//$'/'/$'\/'}
        # Check if this sbinary wasn't already handled in some of the previous iterations
        # Return match only if whole sbinary definition matched (not in the case just prefix matched!!!)
        if [[ $(sed -ne "/${sbinary_esc}$/p" <<< ${sbinaries_to_skip[@]}) ]]
        then
                # If so, don't process it second time & go to process next sbinary
                continue
        fi

        # Reset the counter of inspected files when starting to check
        # presence of existing audit rule for new sbinary
        local count_of_inspected_files=0

        # For each audit rules file from the list of files to be inspected
        for afile in "${files_to_inspect[@]}"
        do

                # Search current audit rules file's content for match. Match criteria:
                # * existing rule is for the same SUID/SGID binary we are currently processing (but
                #   can contain multiple -F path= elements covering multiple SUID/SGID binaries)
                # * existing rule contains all arguments from expected rule form (though can contain
                #   them in arbitrary order)

                base_search=$(sed -e "/-a always,exit/!d" -e "/-F path=${sbinary_esc}$/!d"   \
                                  -e "/-F path=[^[:space:]]\+/!d" -e "/-F perm=.*/!d"       \
                                  -e "/-F auid>=${min_auid}/!d" -e "/-F auid!=4294967295/!d"  \
                                  -e "/-k privileged/!d" $afile)

                # Increase the count of inspected files for this sbinary
                count_of_inspected_files=$((count_of_inspected_files + 1))

                # Define expected rule form for this binary
                expected_rule="-a always,exit -F path=${sbinary} -F perm=x -F auid>=${min_auid} -F auid!=4294967295 -k privileged"

                # Require execute access type to be set for existing audit rule
                exec_access='x'

                # Search current audit rules file's content for presence of rule pattern for this sbinary
                if [[ $base_search ]]
                then

                        # Current audit rules file already contains rule for this binary =>
                        # Store the exact form of found rule for this binary for further processing
                        concrete_rule=$base_search

                        # Select all other SUID/SGID binaries possibly also present in the found rule
                        IFS=$'\n' handled_sbinaries=($(grep -o -e "-F path=[^[:space:]]\+" <<< $concrete_rule))
                        IFS=$' ' handled_sbinaries=(${handled_sbinaries[@]//-F path=/})

                        # Merge the list of such SUID/SGID binaries found in this iteration with global list ignoring duplicates
                        sbinaries_to_skip=($(for i in "${sbinaries_to_skip[@]}" "${handled_sbinaries[@]}"; do echo $i; done | sort -du))

                        # Separate concrete_rule into three sections using hash '#'
                        # sign as a delimiter around rule's permission section borders
                        concrete_rule=$(echo $concrete_rule | sed -n "s/\(.*\)\+\(-F perm=[rwax]\+\)\+/\1#\2#/p")

                        # Split concrete_rule into head, perm, and tail sections using hash '#' delimiter
                        IFS=$'#' read rule_head rule_perm rule_tail <<<  "$concrete_rule"

                        # Extract already present exact access type [r|w|x|a] from rule's permission section
                        access_type=${rule_perm//-F perm=/}

                        # Verify current permission access type(s) for rule contain 'x' (execute) permission
                        if ! grep -q "$exec_access" <<< "$access_type"
                        then

                                # If not, append the 'x' (execute) permission to the existing access type bits
                                access_type="$access_type$exec_access"
                                # Reconstruct the permissions section for the rule
                                new_rule_perm="-F perm=$access_type"
                                # Update existing rule in current audit rules file with the new permission section
                                sed -i "s#${rule_head}\(.*\)${rule_tail}#${rule_head}${new_rule_perm}${rule_tail}#" $afile

                        fi

                # If the required audit rule for particular sbinary wasn't found yet, insert it under following conditions:
                #
                # * in the "auditctl" mode of operation insert particular rule each time
                #   (because in this mode there's only one file -- /etc/audit/audit.rules to be inspected for presence of this rule),
                #
                # * in the "augenrules" mode of operation insert particular rule only once and only in case we have already
                #   searched all of the files from /etc/audit/rules.d/*.rules location (since that audit rule can be defined
                #   in any of those files and if not, we want it to be inserted only once into /etc/audit/rules.d/privileged.rules file)
                #
                elif [ "$tool" == "auditctl" ] || [[ "$tool" == "augenrules" && $count_of_inspected_files -eq "${#files_to_inspect[@]}" ]]
                then

                        # Current audit rules file's content doesn't contain expected rule for this
                        # SUID/SGID binary yet => append it
                        echo $expected_rule >> $output_audit_file
                fi

        done

done

}

perform_audit_rules_privileged_commands_remediation "auditctl" "1000"
perform_audit_rules_privileged_commands_remediation "augenrules" "1000"


# Perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S .* -F auid>=1000 -F auid!=4294967295 -k *"
	GROUP="mount"
	FULL_RULE="-a always,exit -F arch=$ARCH -S mount -F auid>=1000 -F auid!=4294967295 -k export"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done


# Perform the remediation for the syscall rule
# Retrieve hardware architecture of the underlying system
[ $(getconf LONG_BIT) = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S .* -F auid>=1000 -F auid!=4294967295 -k *"
	# Use escaped BRE regex to specify rule group
	GROUP="\(rmdir\|unlink\|rename\)"
	FULL_RULE="-a always,exit -F arch=$ARCH -S rmdir -S unlink -S unlinkat -S rename -S renameat -F auid>=1000 -F auid!=4294967295 -k delete"
	# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

	fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
	fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done


# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/etc/sudoers" "wa" "actions"
fix_audit_watch_rule "augenrules" "/etc/sudoers" "wa" "actions"


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
# Note: 32-bit kernel modules can't be loaded / unloaded on 64-bit kernel =>
#       it's not required on a 64-bit system to check also for the presence
#       of 32-bit's equivalent of the corresponding rule. Therefore for
#       each system it's enought to check presence of system's native rule form.
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b64")

for ARCH in "${RULE_ARCHS[@]}"
do
        PATTERN="-a always,exit -F arch=$ARCH -S init_module -S delete_module \(-F key=\|-k \).*"
        GROUP="modules"
        FULL_RULE="-a always,exit -F arch=$ARCH -S init_module -S delete_module -k modules"
        # Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_syscall_rule {

# Load function arguments into local variables
local tool="$1"
local pattern="$2"
local group="$3"
local arch="$4"
local full_rule="$5"

# Check sanity of the input
if [ $# -ne "5" ]
then
        echo "Usage: fix_audit_syscall_rule 'tool' 'pattern' 'group' 'arch' 'full rule'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
#  Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#        auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#        augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#        augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
#
declare -a files_to_inspect

# First check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# file to the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules' )
# If audit tool is 'augenrules', then check if the audit rule is defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to the list for inspection
# If rule isn't defined yet, add '/etc/audit/rules.d/$key.rules' to the list for inspection
elif [ "$tool" == 'augenrules' ]
then
        # Extract audit $key from audit rule so we can use it later
        key=$(expr "$full_rule" : '.*-k[[:space:]]\([^[:space:]]\+\)')
        # Check if particular audit rule is already defined
        IFS=$'\n' matches=($(sed -s -n -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d;F" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        for match in "${matches[@]}"
        do
                files_to_inspect=("${files_to_inspect[@]}" "${match}")
        done
        # Case when particular rule isn't defined in /etc/audit/rules.d/*.rules yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

#
# Indicator that we want to append $full_rule into $audit_file by default
local append_expected_rule=0

for audit_file in "${files_to_inspect[@]}"
do

        # Filter existing $audit_file rules' definitions to select those that:
        # * follow the rule pattern, and
        # * meet the hardware architecture requirement, and
        # * are current syscall group specific
        IFS=$'\n' existing_rules=($(sed -e "/${pattern}/!d" -e "/${arch}/!d" -e "/${group}/!d"  "$audit_file"))
        # Reset IFS back to default
        unset IFS

        # Process rules found case-by-case
        for rule in "${existing_rules[@]}"
        do
                # Found rule is for same arch & key, but differs (e.g. in count of -S arguments)
                if [ "${rule}" != "${full_rule}" ]
                then
                        # If so, isolate just '(-S \w)+' substring of that rule
                        rule_syscalls=$(echo $rule | grep -o -P '(-S \w+ )+')
                        # Check if list of '-S syscall' arguments of that rule is subset
                        # of '-S syscall' list of expected $full_rule
                        if grep -q -- "$rule_syscalls" <<< "$full_rule"
                        then
                                # Rule is covered (i.e. the list of -S syscalls for this rule is
                                # subset of -S syscalls of $full_rule => existing rule can be deleted
                                # Thus delete the rule from audit.rules & our array
                                sed -i -e "/$rule/d" "$audit_file"
                                existing_rules=("${existing_rules[@]//$rule/}")
                        else
                                # Rule isn't covered by $full_rule - it besides -S syscall arguments
                                # for this group contains also -S syscall arguments for other syscall
                                # group. Example: '-S lchown -S fchmod -S fchownat' => group='chown'
                                # since 'lchown' & 'fchownat' share 'chown' substring
                                # Therefore:
                                # * 1) delete the original rule from audit.rules
                                # (original '-S lchown -S fchmod -S fchownat' rule would be deleted)
                                # * 2) delete the -S syscall arguments for this syscall group, but
                                # keep those not belonging to this syscall group
                                # (original '-S lchown -S fchmod -S fchownat' would become '-S fchmod'
                                # * 3) append the modified (filtered) rule again into audit.rules
                                # if the same rule not already present
                                #
                                # 1) Delete the original rule
                                sed -i -e "/$rule/d" "$audit_file"
                                # 2) Delete syscalls for this group, but keep those from other groups
                                # Convert current rule syscall's string into array splitting by '-S' delimiter
                                IFS=$'-S' read -a rule_syscalls_as_array <<< "$rule_syscalls"
                                # Reset IFS back to default
                                unset IFS
                                # Declare new empty string to hold '-S syscall' arguments from other groups
                                new_syscalls_for_rule=''
                                # Walk through existing '-S syscall' arguments
                                for syscall_arg in "${rule_syscalls_as_array[@]}"
                                do
                                        # Skip empty $syscall_arg values
                                        if [ "$syscall_arg" == '' ]
                                        then
                                                continue
                                        fi
                                        # If the '-S syscall' doesn't belong to current group add it to the new list
                                        # (together with adding '-S' delimiter back for each of such item found)
                                        if grep -q -v -- "$group" <<< "$syscall_arg"
                                        then
                                                new_syscalls_for_rule="$new_syscalls_for_rule -S $syscall_arg"
                                        fi
                                done
                                # Replace original '-S syscall' list with the new one for this rule
                                updated_rule=${rule//$rule_syscalls/$new_syscalls_for_rule}
                                # Squeeze repeated whitespace characters in rule definition (if any) into one
                                updated_rule=$(echo "$updated_rule" | tr -s '[:space:]')
                                # 3) Append the modified / filtered rule again into audit.rules
                                #    (but only in case it's not present yet to prevent duplicate definitions)
                                if ! grep -q -- "$updated_rule" "$audit_file"
                                then
                                        echo "$updated_rule" >> "$audit_file"
                                fi
                        fi
                else
                        # $audit_file already contains the expected rule form for this
                        # architecture & key => don't insert it second time
                        append_expected_rule=1
                fi
        done

        # We deleted all rules that were subset of the expected one for this arch & key.
        # Also isolated rules containing system calls not from this system calls group.
        # Now append the expected rule if it's not present in $audit_file yet
        if [[ ${append_expected_rule} -eq "0" ]]
        then
                echo "$full_rule" >> "$audit_file"
        fi
done

}

        fix_audit_syscall_rule "auditctl" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
        fix_audit_syscall_rule "augenrules" "$PATTERN" "$GROUP" "$ARCH" "$FULL_RULE"
done

# Then perform the remediations for the watch rules
# Perform the remediation for both possible tools: 'auditctl' and 'augenrules'

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/usr/sbin/insmod" "x" "modules"
fix_audit_watch_rule "augenrules" "/usr/sbin/insmod" "x" "modules"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/usr/sbin/rmmod" "x" "modules"
fix_audit_watch_rule "augenrules" "/usr/sbin/rmmod" "x" "modules"

function fix_audit_watch_rule {

# Load function arguments into local variables
local tool="$1"
local path="$2"
local required_access_bits="$3"
local key="$4"

# Check sanity of the input
if [ $# -ne "4" ]
then
        echo "Usage: fix_audit_watch_rule 'tool' 'path' 'bits' 'key'"
        echo "Aborting."
        exit 1
fi

# Create a list of audit *.rules files that should be inspected for presence and correctness
# of a particular audit rule. The scheme is as follows:
#
# -----------------------------------------------------------------------------------------
# Tool used to load audit rules | Rule already defined  |  Audit rules file to inspect    |
# -----------------------------------------------------------------------------------------
#       auditctl                |     Doesn't matter    |  /etc/audit/audit.rules         |
# -----------------------------------------------------------------------------------------
#       augenrules              |          Yes          |  /etc/audit/rules.d/*.rules     |
#       augenrules              |          No           |  /etc/audit/rules.d/$key.rules  |
# -----------------------------------------------------------------------------------------
declare -a files_to_inspect

# Check sanity of the specified audit tool
if [ "$tool" != 'auditctl' ] && [ "$tool" != 'augenrules' ]
then
        echo "Unknown audit rules loading tool: $1. Aborting."
        echo "Use either 'auditctl' or 'augenrules'!"
        exit 1
# If the audit tool is 'auditctl', then add '/etc/audit/audit.rules'
# into the list of files to be inspected
elif [ "$tool" == 'auditctl' ]
then
        files_to_inspect=("${files_to_inspect[@]}" '/etc/audit/audit.rules')
# If the audit is 'augenrules', then check if rule is already defined
# If rule is defined, add '/etc/audit/rules.d/*.rules' to list of files for inspection.
# If rule isn't defined, add '/etc/audit/rules.d/$key.rules' to list of files for inspection.
elif [ "$tool" == 'augenrules' ]
then
        # Case when particular audit rule is already defined in some of /etc/audit/rules.d/*.rules file
        # Get pair -- filepath : matching_row into @matches array
        IFS=$'\n' matches=($(grep -P "[\s]*-w[\s]+$path" /etc/audit/rules.d/*.rules))
        # Reset IFS back to default
        unset IFS
        # For each of the matched entries
        for match in "${matches[@]}"
        do
                # Extract filepath from the match
                rulesd_audit_file=$(echo $match | cut -f1 -d ':')
                # Append that path into list of files for inspection
                files_to_inspect=("${files_to_inspect[@]}" "$rulesd_audit_file")
        done
        # Case when particular audit rule isn't defined yet
        if [ ${#files_to_inspect[@]} -eq "0" ]
        then
                # Append '/etc/audit/rules.d/$key.rules' into list of files for inspection
                files_to_inspect="/etc/audit/rules.d/$key.rules"
                # If the $key.rules file doesn't exist yet, create it with correct permissions
                if [ ! -e "$files_to_inspect" ]
                then
                        touch "$files_to_inspect"
                        chmod 0640 "$files_to_inspect"
                fi
        fi
fi

# Finally perform the inspection and possible subsequent audit rule
# correction for each of the files previously identified for inspection
for audit_rules_file in "${files_to_inspect[@]}"
do

        # Check if audit watch file system object rule for given path already present
        if grep -q -P -- "[\s]*-w[\s]+$path" "$audit_rules_file"
        then
                # Rule is found => verify yet if existing rule definition contains
                # all of the required access type bits

                # Escape slashes in path for use in sed pattern below
                local esc_path=${path//$'/'/$'\/'}
                # Define BRE whitespace class shortcut
                local sp="[[:space:]]"
                # Extract current permission access types (e.g. -p [r|w|x|a] values) from audit rule
                current_access_bits=$(sed -ne "s/$sp*-w$sp\+$esc_path$sp\+-p$sp\+\([rxwa]\{1,4\}\).*/\1/p" "$audit_rules_file")
                # Split required access bits string into characters array
                # (to check bit's presence for one bit at a time)
                for access_bit in $(echo "$required_access_bits" | grep -o .)
                do
                        # For each from the required access bits (e.g. 'w', 'a') check
                        # if they are already present in current access bits for rule.
                        # If not, append that bit at the end
                        if ! grep -q "$access_bit" <<< "$current_access_bits"
                        then
                                # Concatenate the existing mask with the missing bit
                                current_access_bits="$current_access_bits$access_bit"
                        fi
                done
                # Propagate the updated rule's access bits (original + the required
                # ones) back into the /etc/audit/audit.rules file for that rule
                sed -i "s/\($sp*-w$sp\+$esc_path$sp\+-p$sp\+\)\([rxwa]\{1,4\}\)\(.*\)/\1$current_access_bits\3/" "$audit_rules_file"
        else
                # Rule isn't present yet. Append it at the end of $audit_rules_file file
                # with proper key

                echo "-w $path -p $required_access_bits -k $key" >> "$audit_rules_file"
        fi
done
}

fix_audit_watch_rule "auditctl" "/usr/sbin/modprobe" "x" "modules"
fix_audit_watch_rule "augenrules" "/usr/sbin/modprobe" "x" "modules"

# Traverse all of:
#
# /etc/audit/audit.rules,			(for auditctl case)
# /etc/audit/rules.d/*.rules			(for augenrules case)
#
# files to check if '-e .*' setting is present in that '*.rules' file already.
# If found, delete such occurrence since auditctl(8) manual page instructs the
# '-e 2' rule should be placed as the last rule in the configuration
find /etc/audit /etc/audit/rules.d -maxdepth 1 -type f -name *.rules -exec sed -i '/-e[[:space:]]\+.*/d' {} ';'

# Append '-e 2' requirement at the end of both:
# * /etc/audit/audit.rules file 		(for auditctl case)
# * /etc/audit/rules.d/immutable.rules		(for augenrules case)

for AUDIT_FILE in "/etc/audit/audit.rules" "/etc/audit/rules.d/immutable.rules"
do
	echo '' >> $AUDIT_FILE
	echo '# Set the audit.rules configuration immutable per security requirements' >> $AUDIT_FILE
	echo '# Reboot is required to change audit rules once this setting is applied' >> $AUDIT_FILE
	echo '-e 2' >> $AUDIT_FILE
done

function replace_or_append {
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  # Check sanity of the input
  if [ $# -lt "3" ]
  then
        echo "Usage: replace_or_append 'config_file_location' 'key_to_search' 'new_value'"
        echo
        echo "If symlinks need to be taken into account, add yes/no to the last argument"
        echo "to allow to 'follow_symlinks'."
        echo "Aborting."
        exit 1
  fi

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  if test -L $config_file; then
    sed_command="sed -i --follow-symlinks"
  else
    sed_command="sed -i"
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if ! [ "x$cce" = x ] && [ "$cce" != '@CCENUM@' ]; then
    cce="CCE-${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed "s/[\^=\$,;+]*//g" <<< $key)

  # If there is no print format specified in the last arg, use the default format.
  if ! [ "x$format" = x ] ; then
    printf -v formatted_output "$format" "$stripped_key" "$value"
  else
    formatted_output="$stripped_key = $value"
  fi

  # If the key exists, change it. Otherwise, add it to the config_file.
  if `grep -qi $key $config_file` ; then
    $sed_command "s/$key.*/$formatted_output/g" $config_file
  else
    # \n is precaution for case where file ends without trailing newline
    echo -e "\n# Per $cce: Set $formatted_output in $config_file" >> $config_file
    echo -e "$formatted_output" >> $config_file
  fi

}

replace_or_append '/etc/ssh/sshd_config' '^Protocol' '2' 'CCE-27320-1' '%s %s'

sshd_idle_timeout_value="300"

function replace_or_append {
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  # Check sanity of the input
  if [ $# -lt "3" ]
  then
        echo "Usage: replace_or_append 'config_file_location' 'key_to_search' 'new_value'"
        echo
        echo "If symlinks need to be taken into account, add yes/no to the last argument"
        echo "to allow to 'follow_symlinks'."
        echo "Aborting."
        exit 1
  fi

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  if test -L $config_file; then
    sed_command="sed -i --follow-symlinks"
  else
    sed_command="sed -i"
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if ! [ "x$cce" = x ] && [ "$cce" != '@CCENUM@' ]; then
    cce="CCE-${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed "s/[\^=\$,;+]*//g" <<< $key)

  # If there is no print format specified in the last arg, use the default format.
  if ! [ "x$format" = x ] ; then
    printf -v formatted_output "$format" "$stripped_key" "$value"
  else
    formatted_output="$stripped_key = $value"
  fi

  # If the key exists, change it. Otherwise, add it to the config_file.
  if `grep -qi $key $config_file` ; then
    $sed_command "s/$key.*/$formatted_output/g" $config_file
  else
    # \n is precaution for case where file ends without trailing newline
    echo -e "\n# Per $cce: Set $formatted_output in $config_file" >> $config_file
    echo -e "$formatted_output" >> $config_file
  fi

}

replace_or_append '/etc/ssh/sshd_config' '^ClientAliveInterval' $sshd_idle_timeout_value 'CCE-27433-2' '%s %s'

function replace_or_append {
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  # Check sanity of the input
  if [ $# -lt "3" ]
  then
        echo "Usage: replace_or_append 'config_file_location' 'key_to_search' 'new_value'"
        echo
        echo "If symlinks need to be taken into account, add yes/no to the last argument"
        echo "to allow to 'follow_symlinks'."
        echo "Aborting."
        exit 1
  fi

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  if test -L $config_file; then
    sed_command="sed -i --follow-symlinks"
  else
    sed_command="sed -i"
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if ! [ "x$cce" = x ] && [ "$cce" != '@CCENUM@' ]; then
    cce="CCE-${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed "s/[\^=\$,;+]*//g" <<< $key)

  # If there is no print format specified in the last arg, use the default format.
  if ! [ "x$format" = x ] ; then
    printf -v formatted_output "$format" "$stripped_key" "$value"
  else
    formatted_output="$stripped_key = $value"
  fi

  # If the key exists, change it. Otherwise, add it to the config_file.
  if `grep -qi $key $config_file` ; then
    $sed_command "s/$key.*/$formatted_output/g" $config_file
  else
    # \n is precaution for case where file ends without trailing newline
    echo -e "\n# Per $cce: Set $formatted_output in $config_file" >> $config_file
    echo -e "$formatted_output" >> $config_file
  fi

}

replace_or_append '/etc/ssh/sshd_config' '^ClientAliveCountMax' '0' 'CCE-27082-7' '%s %s'

function replace_or_append {
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  # Check sanity of the input
  if [ $# -lt "3" ]
  then
        echo "Usage: replace_or_append 'config_file_location' 'key_to_search' 'new_value'"
        echo
        echo "If symlinks need to be taken into account, add yes/no to the last argument"
        echo "to allow to 'follow_symlinks'."
        echo "Aborting."
        exit 1
  fi

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  if test -L $config_file; then
    sed_command="sed -i --follow-symlinks"
  else
    sed_command="sed -i"
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if ! [ "x$cce" = x ] && [ "$cce" != '@CCENUM@' ]; then
    cce="CCE-${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed "s/[\^=\$,;+]*//g" <<< $key)

  # If there is no print format specified in the last arg, use the default format.
  if ! [ "x$format" = x ] ; then
    printf -v formatted_output "$format" "$stripped_key" "$value"
  else
    formatted_output="$stripped_key = $value"
  fi

  # If the key exists, change it. Otherwise, add it to the config_file.
  if `grep -qi $key $config_file` ; then
    $sed_command "s/$key.*/$formatted_output/g" $config_file
  else
    # \n is precaution for case where file ends without trailing newline
    echo -e "\n# Per $cce: Set $formatted_output in $config_file" >> $config_file
    echo -e "$formatted_output" >> $config_file
  fi

}

replace_or_append '/etc/ssh/sshd_config' '^IgnoreRhosts' 'yes' 'CCE-27377-1' '%s %s'
grep -q ^HostbasedAuthentication /etc/ssh/sshd_config && \
  sed -i "s/HostbasedAuthentication.*/HostbasedAuthentication no/g" /etc/ssh/sshd_config
if ! [ $? -eq 0 ]; then
    echo "HostbasedAuthentication no" >> /etc/ssh/sshd_config
fi

SSHD_CONFIG='/etc/ssh/sshd_config'

# Obtain line number of first uncommented case-insensitive occurrence of Match
# block directive (possibly prefixed with whitespace) present in $SSHD_CONFIG
FIRST_MATCH_BLOCK=$(sed -n '/^[[:space:]]*Match[^\n]*/I{=;q}' $SSHD_CONFIG)

# Obtain line number of first uncommented case-insensitive occurence of
# PermitRootLogin directive (possibly prefixed with whitespace) present in
# $SSHD_CONFIG
FIRST_PERMIT_ROOT_LOGIN=$(sed -n '/^[[:space:]]*PermitRootLogin[^\n]*/I{=;q}' $SSHD_CONFIG)

# Case: Match block directive not present in $SSHD_CONFIG
if [ -z "$FIRST_MATCH_BLOCK" ]
then

    # Case: PermitRootLogin directive not present in $SSHD_CONFIG yet
    if [ -z "$FIRST_PERMIT_ROOT_LOGIN" ]
    then
        # Append 'PermitRootLogin no' at the end of $SSHD_CONFIG
        echo -e "\nPermitRootLogin no" >> $SSHD_CONFIG

    # Case: PermitRootLogin directive present in $SSHD_CONFIG already
    else
        # Replace first uncommented case-insensitive occurrence
        # of PermitRootLogin directive
        sed -i "$FIRST_PERMIT_ROOT_LOGIN s/^[[:space:]]*PermitRootLogin.*$/PermitRootLogin no/I" $SSHD_CONFIG
    fi

# Case: Match block directive present in $SSHD_CONFIG
else

    # Case: PermitRootLogin directive not present in $SSHD_CONFIG yet
    if [ -z "$FIRST_PERMIT_ROOT_LOGIN" ]
    then
        # Prepend 'PermitRootLogin no' before first uncommented
        # case-insensitive occurrence of Match block directive
        sed -i "$FIRST_MATCH_BLOCK s/^\([[:space:]]*Match[^\n]*\)/PermitRootLogin no\n\1/I" $SSHD_CONFIG

    # Case: PermitRootLogin directive present in $SSHD_CONFIG and placed
    #       before first Match block directive
    elif [ "$FIRST_PERMIT_ROOT_LOGIN" -lt "$FIRST_MATCH_BLOCK" ]
    then
        # Replace first uncommented case-insensitive occurrence
        # of PermitRootLogin directive
        sed -i "$FIRST_PERMIT_ROOT_LOGIN s/^[[:space:]]*PermitRootLogin.*$/PermitRootLogin no/I" $SSHD_CONFIG

    # Case: PermitRootLogin directive present in $SSHD_CONFIG and placed
    # after first Match block directive
    else
         # Prepend 'PermitRootLogin no' before first uncommented
         # case-insensitive occurrence of Match block directive
         sed -i "$FIRST_MATCH_BLOCK s/^\([[:space:]]*Match[^\n]*\)/PermitRootLogin no\n\1/I" $SSHD_CONFIG
    fi
fi

function replace_or_append {
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  # Check sanity of the input
  if [ $# -lt "3" ]
  then
        echo "Usage: replace_or_append 'config_file_location' 'key_to_search' 'new_value'"
        echo
        echo "If symlinks need to be taken into account, add yes/no to the last argument"
        echo "to allow to 'follow_symlinks'."
        echo "Aborting."
        exit 1
  fi

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  if test -L $config_file; then
    sed_command="sed -i --follow-symlinks"
  else
    sed_command="sed -i"
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if ! [ "x$cce" = x ] && [ "$cce" != '@CCENUM@' ]; then
    cce="CCE-${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed "s/[\^=\$,;+]*//g" <<< $key)

  # If there is no print format specified in the last arg, use the default format.
  if ! [ "x$format" = x ] ; then
    printf -v formatted_output "$format" "$stripped_key" "$value"
  else
    formatted_output="$stripped_key = $value"
  fi

  # If the key exists, change it. Otherwise, add it to the config_file.
  if `grep -qi $key $config_file` ; then
    $sed_command "s/$key.*/$formatted_output/g" $config_file
  else
    # \n is precaution for case where file ends without trailing newline
    echo -e "\n# Per $cce: Set $formatted_output in $config_file" >> $config_file
    echo -e "$formatted_output" >> $config_file
  fi

}

replace_or_append '/etc/ssh/sshd_config' '^PermitEmptyPasswords' 'no' 'CCE-27471-2' '%s %s'

function replace_or_append {
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  # Check sanity of the input
  if [ $# -lt "3" ]
  then
        echo "Usage: replace_or_append 'config_file_location' 'key_to_search' 'new_value'"
        echo
        echo "If symlinks need to be taken into account, add yes/no to the last argument"
        echo "to allow to 'follow_symlinks'."
        echo "Aborting."
        exit 1
  fi

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  if test -L $config_file; then
    sed_command="sed -i --follow-symlinks"
  else
    sed_command="sed -i"
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if ! [ "x$cce" = x ] && [ "$cce" != '@CCENUM@' ]; then
    cce="CCE-${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed "s/[\^=\$,;+]*//g" <<< $key)

  # If there is no print format specified in the last arg, use the default format.
  if ! [ "x$format" = x ] ; then
    printf -v formatted_output "$format" "$stripped_key" "$value"
  else
    formatted_output="$stripped_key = $value"
  fi

  # If the key exists, change it. Otherwise, add it to the config_file.
  if `grep -qi $key $config_file` ; then
    $sed_command "s/$key.*/$formatted_output/g" $config_file
  else
    # \n is precaution for case where file ends without trailing newline
    echo -e "\n# Per $cce: Set $formatted_output in $config_file" >> $config_file
    echo -e "$formatted_output" >> $config_file
  fi

}

replace_or_append '/etc/ssh/sshd_config' '^Banner' '/etc/issue' 'CCE-27314-4' '%s %s'

function replace_or_append {
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  # Check sanity of the input
  if [ $# -lt "3" ]
  then
        echo "Usage: replace_or_append 'config_file_location' 'key_to_search' 'new_value'"
        echo
        echo "If symlinks need to be taken into account, add yes/no to the last argument"
        echo "to allow to 'follow_symlinks'."
        echo "Aborting."
        exit 1
  fi

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  if test -L $config_file; then
    sed_command="sed -i --follow-symlinks"
  else
    sed_command="sed -i"
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if ! [ "x$cce" = x ] && [ "$cce" != '@CCENUM@' ]; then
    cce="CCE-${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed "s/[\^=\$,;+]*//g" <<< $key)

  # If there is no print format specified in the last arg, use the default format.
  if ! [ "x$format" = x ] ; then
    printf -v formatted_output "$format" "$stripped_key" "$value"
  else
    formatted_output="$stripped_key = $value"
  fi

  # If the key exists, change it. Otherwise, add it to the config_file.
  if `grep -qi $key $config_file` ; then
    $sed_command "s/$key.*/$formatted_output/g" $config_file
  else
    # \n is precaution for case where file ends without trailing newline
    echo -e "\n# Per $cce: Set $formatted_output in $config_file" >> $config_file
    echo -e "$formatted_output" >> $config_file
  fi

}

replace_or_append '/etc/ssh/sshd_config' '^PermitUserEnvironment' 'no' 'CCE-27363-1' '%s %s'

function replace_or_append {
  local config_file=$1
  local key=$2
  local value=$3
  local cce=$4
  local format=$5

  # Check sanity of the input
  if [ $# -lt "3" ]
  then
        echo "Usage: replace_or_append 'config_file_location' 'key_to_search' 'new_value'"
        echo
        echo "If symlinks need to be taken into account, add yes/no to the last argument"
        echo "to allow to 'follow_symlinks'."
        echo "Aborting."
        exit 1
  fi

  # Test if the config_file is a symbolic link. If so, use --follow-symlinks with sed.
  # Otherwise, regular sed command will do.
  if test -L $config_file; then
    sed_command="sed -i --follow-symlinks"
  else
    sed_command="sed -i"
  fi

  # Test that the cce arg is not empty or does not equal @CCENUM@.
  # If @CCENUM@ exists, it means that there is no CCE assigned.
  if ! [ "x$cce" = x ] && [ "$cce" != '@CCENUM@' ]; then
    cce="CCE-${cce}"
  else
    cce="CCE"
  fi

  # Strip any search characters in the key arg so that the key can be replaced without
  # adding any search characters to the config file.
  stripped_key=$(sed "s/[\^=\$,;+]*//g" <<< $key)

  # If there is no print format specified in the last arg, use the default format.
  if ! [ "x$format" = x ] ; then
    printf -v formatted_output "$format" "$stripped_key" "$value"
  else
    formatted_output="$stripped_key = $value"
  fi

  # If the key exists, change it. Otherwise, add it to the config_file.
  if `grep -qi $key $config_file` ; then
    $sed_command "s/$key.*/$formatted_output/g" $config_file
  else
    # \n is precaution for case where file ends without trailing newline
    echo -e "\n# Per $cce: Set $formatted_output in $config_file" >> $config_file
    echo -e "$formatted_output" >> $config_file
  fi

}

replace_or_append '/etc/ssh/sshd_config' '^Ciphers' 'aes128-ctr,aes192-ctr,aes256-ctr,aes128-cbc,3des-cbc,aes192-cbc,aes256-cbc' 'CCE-27295-5' '%s %s'
