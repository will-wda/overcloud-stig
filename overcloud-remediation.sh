
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

if grep --silent ^clean_requirements_on_remove /etc/yum.conf ; then
        sed -i "s/^clean_requirements_on_remove.*/clean_requirements_on_remove=1/g" /etc/yum.conf
else
        echo -e "\n# Set clean_requirements_on_remove to 1 per security requirements" >> /etc/yum.conf
        echo "clean_requirements_on_remove=1" >> /etc/yum.conf
fi

if grep --silent ^localpkg_gpgcheck /etc/yum.conf ; then
        sed -i "s/^localpkg_gpgcheck.*/localpkg_gpgcheck=1/g" /etc/yum.conf
else
        echo -e "\n# Set localpkg_gpgcheck to 1 per security requirements" >> /etc/yum.conf
        echo "localpkg_gpgcheck=1" >> /etc/yum.conf
fi

if grep --silent ^repo_gpgcheck /etc/yum.conf ; then
        sed -i "s/^repo_gpgcheck.*/repo_gpgcheck=1/g" /etc/yum.conf
else
        echo -e "\n# Set repo_gpgcheck to 1 per security requirements" >> /etc/yum.conf
        echo "repo_gpgcheck=1" >> /etc/yum.conf
fi
echo "05 4 * * * root /usr/sbin/aide --check" >> /etc/crontab
CRONTAB=/etc/crontab
CRONDIRS='/etc/cron.d /etc/cron.daily /etc/cron.weekly /etc/cron.monthly'

if [ -f /var/spool/cron/root ]; then
	VARSPOOL=/var/spool/cron/root
fi

if ! grep -qR '^.*\/usr\/sbin\/aide\s*\-\-check.*\|.*\/bin\/mail\s*-s\s*".*"\s*root@.*$' $CRONTAB $VARSPOOL $CRONDIRS; then
	echo '0 5 * * * /usr/sbin/aide  --check | /bin/mail -s "$(hostname) - AIDE Integrity Check" root@localhost' >> $CRONTAB
fi


aide_conf="/etc/aide.conf"

groups=$(grep "^[A-Z]\+" $aide_conf | grep -v "^ALLXTRAHASHES" | cut -f1 -d '=' | tr -d ' ' | sort -u)

for group in $groups
do
	config=$(grep "^$group\s*=" $aide_conf | cut -f2 -d '=' | tr -d ' ')

	if ! [[ $config = *acl* ]]
	then
		if [[ -z $config ]]
		then
			config="acl"
		else
			config=$config"+acl"
		fi
	fi
	sed -i "s/^$group\s*=.*/$group = $config/g" $aide_conf
done

aide_conf="/etc/aide.conf"

groups=$(grep "^[A-Z]\+" $aide_conf | grep -v "^ALLXTRAHASHES" | cut -f1 -d '=' | tr -d ' ' | sort -u)

for group in $groups
do
	config=$(grep "^$group\s*=" $aide_conf | cut -f2 -d '=' | tr -d ' ')

	if ! [[ $config = *xattrs* ]]
	then
		if [[ -z $config ]]
		then
			config="xattrs"
		else
			config=$config"+xattrs"
		fi
	fi
	sed -i "s/^$group\s*=.*/$group = $config/g" $aide_conf
done

aide_conf="/etc/aide.conf"
forbidden_hashes=(sha1 rmd160 sha256 whirlpool tiger haval gost crc32)

groups=$(grep "^[A-Z]\+" $aide_conf | cut -f1 -d ' ' | tr -d ' ' | sort -u)

for group in $groups
do
	config=$(grep "^$group\s*=" $aide_conf | cut -f2 -d '=' | tr -d ' ')

	if ! [[ $config = *sha512* ]]
	then
		config=$config"+sha512"
	fi

	for hash in ${forbidden_hashes[@]}
	do
		config=$(echo $config | sed "s/$hash//")
	done

	config=$(echo $config | sed "s/^\+*//")
	config=$(echo $config | sed "s/\+\++/+/")
	config=$(echo $config | sed "s/\+$//")

	sed -i "s/^$group\s*=.*/$group = $config/g" $aide_conf
done

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


if grep --silent ^PRELINKING /etc/sysconfig/prelink ; then
        sed -i "s/^PRELINKING.*/PRELINKING=no/g" /etc/sysconfig/prelink
else
        echo -e "\n# Set PRELINKING to 'no' per security requirements" >> /etc/sysconfig/prelink
        echo "PRELINKING=no" >> /etc/sysconfig/prelink
fi

prelink -u -a

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

var_removable_partition="/dev/cdrom"

NEW_OPT="nosuid"

if [ $(grep "$var_removable_partition" /etc/fstab | grep -c "$NEW_OPT" ) -eq 0 ]; then
  MNT_OPTS=$(grep "$var_removable_partition" /etc/fstab | awk '{print $4}')
  sed -i "s|\($var_removable_partition.*${MNT_OPTS}\)|\1,${NEW_OPT}|" /etc/fstab
fi
if grep --silent "^install usb-storage" /etc/modprobe.d/usb-storage.conf ; then
        sed -i 's/^install usb-storage.*/install usb-storage /bin/true/g' /etc/modprobe.d/usb-storage.conf
else
        echo -e "\n# Disable per security requirements" >> /etc/modprobe.d/usb-storage.conf
        echo "install usb-storage /bin/true" >> /etc/modprobe.d/usb-storage.conf
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

service_command disable autofs

var_selinux_state="enforcing"

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

replace_or_append '/etc/sysconfig/selinux' '^SELINUX=' $var_selinux_state 'CCE-27334-2' '%s=%s'

fixfiles onboot
fixfiles -f relabel

var_selinux_policy_name="targeted"

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

replace_or_append '/etc/sysconfig/selinux' '^SELINUXTYPE=' $var_selinux_policy_name 'CCE-27279-9' '%s=%s'
awk -F: '$3 == 0 && $1 != "root" { print $1 }' /etc/passwd | xargs passwd -l
sed --follow-symlinks -i 's/\<nullok\>//g' /etc/pam.d/system-auth

var_accounts_minimum_age_login_defs="1"

grep -q ^PASS_MIN_DAYS /etc/login.defs && \
  sed -i "s/PASS_MIN_DAYS.*/PASS_MIN_DAYS     $var_accounts_minimum_age_login_defs/g" /etc/login.defs
if ! [ $? -eq 0 ]; then
    echo "PASS_MIN_DAYS      $var_accounts_minimum_age_login_defs" >> /etc/login.defs
fi

var_accounts_maximum_age_login_defs="60"

grep -q ^PASS_MAX_DAYS /etc/login.defs && \
  sed -i "s/PASS_MAX_DAYS.*/PASS_MAX_DAYS     $var_accounts_maximum_age_login_defs/g" /etc/login.defs
if ! [ $? -eq 0 ]; then
    echo "PASS_MAX_DAYS      $var_accounts_maximum_age_login_defs" >> /etc/login.defs
fi

var_account_disable_post_pw_expiration="0"

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

replace_or_append /etc/default/useradd INACTIVE "$var_account_disable_post_pw_expiration" '' '%s=%s'

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

var_password_pam_retry="3"

if grep -q "retry=" /etc/pam.d/system-auth; then   
	sed -i --follow-symlinks "s/\(retry *= *\).*/\1$var_password_pam_retry/" /etc/pam.d/system-auth
else
	sed -i --follow-symlinks "/pam_pwquality.so/ s/$/ retry=$var_password_pam_retry/" /etc/pam.d/system-auth
fi

var_password_pam_maxrepeat="2"

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

replace_or_append '/etc/security/pwquality.conf' '^maxrepeat' $var_password_pam_maxrepeat 'CCE-27333-4' '%s = %s'

var_password_pam_maxclassrepeat="4"

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

replace_or_append '/etc/security/pwquality.conf' '^maxclassrepeat' $var_password_pam_maxclassrepeat 'CCE-27512-3' '%s = %s'

var_password_pam_dcredit="-1"

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

replace_or_append '/etc/security/pwquality.conf' '^dcredit' $var_password_pam_dcredit 'CCE-27214-6' '%s = %s'

var_password_pam_minlen="15"

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

replace_or_append '/etc/security/pwquality.conf' '^minlen' $var_password_pam_minlen 'CCE-27293-0' '%s = %s'

var_password_pam_ucredit="-1"

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

replace_or_append '/etc/security/pwquality.conf' '^ucredit' $var_password_pam_ucredit 'CCE-27200-5' '%s = %s'

var_password_pam_ocredit="-1"

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

replace_or_append '/etc/security/pwquality.conf' '^ocredit' $var_password_pam_ocredit 'CCE-27360-7' '%s = %s'

var_password_pam_lcredit="-1"

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

replace_or_append '/etc/security/pwquality.conf' '^lcredit' $var_password_pam_lcredit 'CCE-27345-8' '%s = %s'

var_password_pam_difok="8"

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

replace_or_append '/etc/security/pwquality.conf' '^difok' $var_password_pam_difok 'CCE-26631-2' '%s = %s'

var_password_pam_minclass="4"

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

replace_or_append '/etc/security/pwquality.conf' '^minclass' $var_password_pam_minclass 'CCE-27115-5' '%s = %s'

var_accounts_passwords_pam_faillock_deny="3"

AUTH_FILES[0]="/etc/pam.d/system-auth"
AUTH_FILES[1]="/etc/pam.d/password-auth"

# This script fixes absence of pam_faillock.so in PAM stack or the
# absense of deny=[0-9]+ in pam_faillock.so arguments
# When inserting auth pam_faillock.so entries,
# the entry with preauth argument will be added before pam_unix.so module
# and entry with authfail argument will be added before pam_deny.so module.

# The placement of pam_faillock.so entries will not be changed
# if they are already present

for pamFile in "${AUTH_FILES[@]}"
do
	
	# pam_faillock.so already present?
	if grep -q "^auth.*pam_faillock.so.*" $pamFile; then

		# pam_faillock.so present, deny directive present?
		if grep -q "^auth.*[default=die].*pam_faillock.so.*authfail.*deny=" $pamFile; then

			# both pam_faillock.so & deny present, just correct deny directive value
			sed -i --follow-symlinks "s/\(^auth.*required.*pam_faillock.so.*preauth.*silent.*\)\(deny *= *\).*/\1\2$var_accounts_passwords_pam_faillock_deny/" $pamFile
			sed -i --follow-symlinks "s/\(^auth.*[default=die].*pam_faillock.so.*authfail.*\)\(deny *= *\).*/\1\2$var_accounts_passwords_pam_faillock_deny/" $pamFile

		# pam_faillock.so present, but deny directive not yet
		else

			# append correct deny value to appropriate places
			sed -i --follow-symlinks "/^auth.*required.*pam_faillock.so.*preauth.*silent.*/ s/$/ deny=$var_accounts_passwords_pam_faillock_deny/" $pamFile
			sed -i --follow-symlinks "/^auth.*[default=die].*pam_faillock.so.*authfail.*/ s/$/ deny=$var_accounts_passwords_pam_faillock_deny/" $pamFile
		fi

	# pam_faillock.so not present yet
	else

		# insert pam_faillock.so preauth row with proper value of the 'deny' option before pam_unix.so
		sed -i --follow-symlinks "/^auth.*pam_unix.so.*/i auth        required      pam_faillock.so preauth silent deny=$var_accounts_passwords_pam_faillock_deny" $pamFile
		# insert pam_faillock.so authfail row with proper value of the 'deny' option before pam_deny.so, after all modules which determine authentication outcome.
		sed -i --follow-symlinks "/^auth.*pam_deny.so.*/i auth        [default=die] pam_faillock.so authfail deny=$var_accounts_passwords_pam_faillock_deny" $pamFile
	fi

	# add pam_faillock.so into account phase
	if ! grep -q "^account.*required.*pam_faillock.so" $pamFile; then
		sed -i --follow-symlinks "/^account.*required.*pam_unix.so/i account     required      pam_faillock.so" $pamFile
	fi
done

var_accounts_passwords_pam_faillock_unlock_time="never"

AUTH_FILES[0]="/etc/pam.d/system-auth"
AUTH_FILES[1]="/etc/pam.d/password-auth"

for pamFile in "${AUTH_FILES[@]}"
do
	
	# pam_faillock.so already present?
	if grep -q "^auth.*pam_faillock.so.*" $pamFile; then

		# pam_faillock.so present, unlock_time directive present?
		if grep -q "^auth.*[default=die].*pam_faillock.so.*authfail.*unlock_time=" $pamFile; then

			# both pam_faillock.so & unlock_time present, just correct unlock_time directive value
			sed -i --follow-symlinks "s/\(^auth.*required.*pam_faillock.so.*preauth.*silent.*\)\(unlock_time *= *\).*/\1\2$var_accounts_passwords_pam_faillock_unlock_time/" $pamFile
			sed -i --follow-symlinks "s/\(^auth.*[default=die].*pam_faillock.so.*authfail.*\)\(unlock_time *= *\).*/\1\2$var_accounts_passwords_pam_faillock_unlock_time/" $pamFile

		# pam_faillock.so present, but unlock_time directive not yet
		else

			# append correct unlock_time value to appropriate places
			sed -i --follow-symlinks "/^auth.*required.*pam_faillock.so.*preauth.*silent.*/ s/$/ unlock_time=$var_accounts_passwords_pam_faillock_unlock_time/" $pamFile
			sed -i --follow-symlinks "/^auth.*[default=die].*pam_faillock.so.*authfail.*/ s/$/ unlock_time=$var_accounts_passwords_pam_faillock_unlock_time/" $pamFile
		fi

	# pam_faillock.so not present yet
	else

		# insert pam_faillock.so preauth & authfail rows with proper value of the 'unlock_time' option
		sed -i --follow-symlinks "/^auth.*sufficient.*pam_unix.so.*/i auth        required      pam_faillock.so preauth silent unlock_time=$var_accounts_passwords_pam_faillock_unlock_time" $pamFile
		sed -i --follow-symlinks "/^auth.*sufficient.*pam_unix.so.*/a auth        [default=die] pam_faillock.so authfail unlock_time=$var_accounts_passwords_pam_faillock_unlock_time" $pamFile
		sed -i --follow-symlinks "/^account.*required.*pam_unix.so/i account     required      pam_faillock.so" $pamFile
	fi
done

AUTH_FILES[0]="/etc/pam.d/system-auth"
AUTH_FILES[1]="/etc/pam.d/password-auth"

# This script fixes absence of pam_faillock.so in PAM stack or the
# absense of even_deny_root and deny=[0-9]+ in pam_faillock.so arguments
# When inserting auth pam_faillock.so entries,
# the entry with preauth argument will be added before pam_unix.so module
# and entry with authfail argument will be added before pam_deny.so module.

# The placement of pam_faillock.so entries will not be changed
# if they are already present

for pamFile in "${AUTH_FILES[@]}"
do
	# pam_faillock.so already present?
	if grep -q "^auth.*pam_faillock.so.*" $pamFile; then

		# pam_faillock.so present, preauth even_deny_root directive present?
		if ! grep -q "^auth.*required.*pam_faillock.so.*preauth.*even_deny_root" $pamFile; then
			# even_deny_root is not present
			sed -i --follow-symlinks "s/\(^auth.*required.*pam_faillock.so.*preauth.*\).*/\1 even_deny_root/" $pamFile
		fi

		# pam_faillock.so present, authfail even_deny_root directive present?
		if ! grep -q "^auth.*\[default=die\].*pam_faillock.so.*authfail.*even_deny_root" $pamFile; then
			# even_deny_root is not present
			sed -i --follow-symlinks "s/\(^auth.*\[default=die\].*pam_faillock.so.*authfail.*silent.*\).*/\1 even_deny_root/" $pamFile
		fi

	# pam_faillock.so not present yet
	else

		# insert pam_faillock.so preauth row with proper value of the 'deny' option before pam_unix.so
		sed -i --follow-symlinks "/^auth.*pam_unix.so.*/i auth        required      pam_faillock.so preauth silent even_deny_root" $pamFile
		# insert pam_faillock.so authfail row with proper value of the 'deny' option before pam_deny.so, after all modules which determine authentication outcome.
		sed -i --follow-symlinks "/^auth.*pam_deny.so.*/i auth        [default=die] pam_faillock.so authfail silent even_deny_root" $pamFile
	fi

done

var_accounts_passwords_pam_faillock_fail_interval="900"

AUTH_FILES[0]="/etc/pam.d/system-auth"
AUTH_FILES[1]="/etc/pam.d/password-auth"

for pamFile in "${AUTH_FILES[@]}"
do
	
	# pam_faillock.so already present?
	if grep -q "^auth.*pam_faillock.so.*" $pamFile; then

		# pam_faillock.so present, 'fail_interval' directive present?
		if grep -q "^auth.*[default=die].*pam_faillock.so.*authfail.*fail_interval=" $pamFile; then

			# both pam_faillock.so & 'fail_interval' present, just correct 'fail_interval' directive value
			sed -i --follow-symlinks "s/\(^auth.*required.*pam_faillock.so.*preauth.*silent.*\)\(fail_interval *= *\).*/\1\2$var_accounts_passwords_pam_faillock_fail_interval/" $pamFile
			sed -i --follow-symlinks "s/\(^auth.*[default=die].*pam_faillock.so.*authfail.*\)\(fail_interval *= *\).*/\1\2$var_accounts_passwords_pam_faillock_fail_interval/" $pamFile

		# pam_faillock.so present, but 'fail_interval' directive not yet
		else

			# append correct 'fail_interval' value to appropriate places
			sed -i --follow-symlinks "/^auth.*required.*pam_faillock.so.*preauth.*silent.*/ s/$/ fail_interval=$var_accounts_passwords_pam_faillock_fail_interval/" $pamFile
			sed -i --follow-symlinks "/^auth.*[default=die].*pam_faillock.so.*authfail.*/ s/$/ fail_interval=$var_accounts_passwords_pam_faillock_fail_interval/" $pamFile
		fi

	# pam_faillock.so not present yet
	else

		# insert pam_faillock.so preauth & authfail rows with proper value of the 'fail_interval' option
		sed -i --follow-symlinks "/^auth.*sufficient.*pam_unix.so.*/i auth        required      pam_faillock.so preauth silent fail_interval=$var_accounts_passwords_pam_faillock_fail_interval" $pamFile
		sed -i --follow-symlinks "/^auth.*sufficient.*pam_unix.so.*/a auth        [default=die] pam_faillock.so authfail fail_interval=$var_accounts_passwords_pam_faillock_fail_interval" $pamFile
		sed -i --follow-symlinks "/^account.*required.*pam_unix.so/i account     required      pam_faillock.so" $pamFile
	fi
done

var_password_pam_unix_remember="5"

if grep -q "remember=" /etc/pam.d/system-auth; then   
	sed -i --follow-symlinks "s/\(^password.*sufficient.*pam_unix.so.*\)\(\(remember *= *\)[^ $]*\)/\1remember=$var_password_pam_unix_remember/" /etc/pam.d/system-auth
else
	sed -i --follow-symlinks "/^password[[:space:]]\+sufficient[[:space:]]\+pam_unix.so/ s/$/ remember=$var_password_pam_unix_remember/" /etc/pam.d/system-auth
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

var_accounts_tmout="600"

if grep --silent ^TMOUT /etc/profile ; then
        sed -i "s/^TMOUT.*/TMOUT=$var_accounts_tmout/g" /etc/profile
else
        echo -e "\n# Set TMOUT to $var_accounts_tmout per security requirements" >> /etc/profile
        echo "TMOUT=$var_accounts_tmout" >> /etc/profile
fi

var_accounts_max_concurrent_login_sessions="10"

if grep -q '^[^#]*\<maxlogins\>' /etc/security/limits.d/*.conf; then
	sed -i "/^[^#]*\<maxlogins\>/ s/maxlogins.*/maxlogins $var_accounts_max_concurrent_login_sessions/" /etc/security/limits.d/*.conf
elif grep -q '^[^#]*\<maxlogins\>' /etc/security/limits.conf; then
	sed -i "/^[^#]*\<maxlogins\>/ s/maxlogins.*/maxlogins $var_accounts_max_concurrent_login_sessions/" /etc/security/limits.conf
else
	echo "*	hard	maxlogins	$var_accounts_max_concurrent_login_sessions" >> /etc/security/limits.conf
fi


# Set variables
var_accounts_fail_delay="4"

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

replace_or_append '/etc/login.defs' '^FAIL_DELAY' "$var_accounts_fail_delay" 'CCE-80352-8' '%s %s'

var_accounts_user_umask="077"

grep -q umask /etc/login.defs && \
  sed -i "s/umask.*/umask $var_accounts_user_umask/g" /etc/login.defs
if ! [ $? -eq 0 ]; then
    echo "umask $var_accounts_user_umask" >> /etc/login.defs
fi
# The process to disable ctrl+alt+del has changed in RHEL7. 
# Reference: https://access.redhat.com/solutions/1123873
ln -sf /dev/null /etc/systemd/system/ctrl-alt-del.target

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

package_command install screen


# Install required packages

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

package_command install esc
package_command install pam_pkcs11

# Enable pcscd.socket systemd activation socket

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

service_command enable pcscd.socket

# Configure the expected /etc/pam.d/system-auth{,-ac} settings directly
#
# The code below will configure system authentication in the way smart card
# logins will be enabled, but also user login(s) via other method to be allowed
#
# NOTE: It is not possible to use the 'authconfig' command to perform the
#       remediation for us, because call of 'authconfig' would discard changes
#       for other remediations (see RH BZ#1357019 for details)
#
#	Therefore we need to configure the necessary settings directly.
#

# Define system-auth config location
SYSTEM_AUTH_CONF="/etc/pam.d/system-auth"
# Define expected 'pam_env.so' row in $SYSTEM_AUTH_CONF
PAM_ENV_SO="auth.*required.*pam_env.so"

# Define 'pam_succeed_if.so' row to be appended past $PAM_ENV_SO row into $SYSTEM_AUTH_CONF
SYSTEM_AUTH_PAM_SUCCEED="\
auth        [success=1 default=ignore] pam_succeed_if.so service notin \
login:gdm:xdm:kdm:xscreensaver:gnome-screensaver:kscreensaver quiet use_uid"
# Define 'pam_pkcs11.so' row to be appended past $SYSTEM_AUTH_PAM_SUCCEED
# row into SYSTEM_AUTH_CONF file
SYSTEM_AUTH_PAM_PKCS11="\
auth        [success=done authinfo_unavail=ignore ignore=ignore default=die] \
pam_pkcs11.so nodebug"

# Define smartcard-auth config location
SMARTCARD_AUTH_CONF="/etc/pam.d/smartcard-auth"
# Define 'pam_pkcs11.so' auth section to be appended past $PAM_ENV_SO into $SMARTCARD_AUTH_CONF
SMARTCARD_AUTH_SECTION="\
auth        [success=done ignore=ignore default=die] pam_pkcs11.so wait_for_card card_only"
# Define expected 'pam_permit.so' row in $SMARTCARD_AUTH_CONF
PAM_PERMIT_SO="account.*required.*pam_permit.so"
# Define 'pam_pkcs11.so' password section
SMARTCARD_PASSWORD_SECTION="\
password    required      pam_pkcs11.so"

# First Correct the SYSTEM_AUTH_CONF configuration
if ! grep -q 'pam_pkcs11.so' "$SYSTEM_AUTH_CONF"
then
	# Append (expected) pam_succeed_if.so row past the pam_env.so into SYSTEM_AUTH_CONF file
	# and append (expected) pam_pkcs11.so row right after the pam_succeed_if.so we just added
	# in SYSTEM_AUTH_CONF file
	# This will preserve any other already existing row equal to "$SYSTEM_AUTH_PAM_SUCCEED"
	echo "$(awk '/^'"$PAM_ENV_SO"'/{print $0 RS "'"$SYSTEM_AUTH_PAM_SUCCEED"'" RS "'"$SYSTEM_AUTH_PAM_PKCS11"'";next}1' "$SYSTEM_AUTH_CONF")" > "$SYSTEM_AUTH_CONF"
fi

# Then also correct the SMARTCARD_AUTH_CONF
if ! grep -q 'pam_pkcs11.so' "$SMARTCARD_AUTH_CONF"
then
	# Append (expected) SMARTCARD_AUTH_SECTION row past the pam_env.so into SMARTCARD_AUTH_CONF file
	sed -i --follow-symlinks -e '/^'"$PAM_ENV_SO"'/a '"$SMARTCARD_AUTH_SECTION" "$SMARTCARD_AUTH_CONF"
	# Append (expected) SMARTCARD_PASSWORD_SECTION row past the pam_permit.so into SMARTCARD_AUTH_CONF file
	sed -i --follow-symlinks -e '/^'"$PAM_PERMIT_SO"'/a '"$SMARTCARD_PASSWORD_SECTION" "$SMARTCARD_AUTH_CONF"
fi

# Perform /etc/pam_pkcs11/pam_pkcs11.conf settings below
# Define selected constants for later reuse
SP="[:space:]"
PAM_PKCS11_CONF="/etc/pam_pkcs11/pam_pkcs11.conf"

# Ensure OCSP is turned on in $PAM_PKCS11_CONF
# 1) First replace any occurrence of 'none' value of 'cert_policy' key setting with the correct configuration
sed -i "s/^[$SP]*cert_policy[$SP]\+=[$SP]\+none;/\t\tcert_policy = ca, ocsp_on, signature;/g" "$PAM_PKCS11_CONF"
# 2) Then append 'ocsp_on' value setting to each 'cert_policy' key in $PAM_PKCS11_CONF configuration line,
# which does not contain it yet
sed -i "/ocsp_on/! s/^[$SP]*cert_policy[$SP]\+=[$SP]\+\(.*\);/\t\tcert_policy = \1, ocsp_on;/" "$PAM_PKCS11_CONF"

login_banner_text="You[\s\n]+are[\s\n]+accessing[\s\n]+a[\s\n]+U.S.[\s\n]+Government[\s\n]+\(USG\)[\s\n]+Information[\s\n]+System[\s\n]+\(IS\)[\s\n]+that[\s\n]+is[\s\n]+provided[\s\n]+for[\s\n]+USG-authorized[\s\n]+use[\s\n]+only.[\s\n]*By[\s\n]+using[\s\n]+this[\s\n]+IS[\s\n]+\(which[\s\n]+includes[\s\n]+any[\s\n]+device[\s\n]+attached[\s\n]+to[\s\n]+this[\s\n]+IS\),[\s\n]+you[\s\n]+consent[\s\n]+to[\s\n]+the[\s\n]+following[\s\n]+conditions\:[\s\n]*-[\s\n]*The[\s\n]+USG[\s\n]+routinely[\s\n]+intercepts[\s\n]+and[\s\n]+monitors[\s\n]+communications[\s\n]+on[\s\n]+this[\s\n]+IS[\s\n]+for[\s\n]+purposes[\s\n]+including,[\s\n]+but[\s\n]+not[\s\n]+limited[\s\n]+to,[\s\n]+penetration[\s\n]+testing,[\s\n]+COMSEC[\s\n]+monitoring,[\s\n]+network[\s\n]+operations[\s\n]+and[\s\n]+defense,[\s\n]+personnel[\s\n]+misconduct[\s\n]+\(PM\),[\s\n]+law[\s\n]+enforcement[\s\n]+\(LE\),[\s\n]+and[\s\n]+counterintelligence[\s\n]+\(CI\)[\s\n]+investigations.[\s\n]*-[\s\n]*At[\s\n]+any[\s\n]+time,[\s\n]+the[\s\n]+USG[\s\n]+may[\s\n]+inspect[\s\n]+and[\s\n]+seize[\s\n]+data[\s\n]+stored[\s\n]+on[\s\n]+this[\s\n]+IS.[\s\n]*-[\s\n]*Communications[\s\n]+using,[\s\n]+or[\s\n]+data[\s\n]+stored[\s\n]+on,[\s\n]+this[\s\n]+IS[\s\n]+are[\s\n]+not[\s\n]+private,[\s\n]+are[\s\n]+subject[\s\n]+to[\s\n]+routine[\s\n]+monitoring,[\s\n]+interception,[\s\n]+and[\s\n]+search,[\s\n]+and[\s\n]+may[\s\n]+be[\s\n]+disclosed[\s\n]+or[\s\n]+used[\s\n]+for[\s\n]+any[\s\n]+USG-authorized[\s\n]+purpose.[\s\n]*-[\s\n]*This[\s\n]+IS[\s\n]+includes[\s\n]+security[\s\n]+measures[\s\n]+\(e.g.,[\s\n]+authentication[\s\n]+and[\s\n]+access[\s\n]+controls\)[\s\n]+to[\s\n]+protect[\s\n]+USG[\s\n]+interests[\s\n]+--[\s\n]+not[\s\n]+for[\s\n]+your[\s\n]+personal[\s\n]+benefit[\s\n]+or[\s\n]+privacy.[\s\n]*-[\s\n]*Notwithstanding[\s\n]+the[\s\n]+above,[\s\n]+using[\s\n]+this[\s\n]+IS[\s\n]+does[\s\n]+not[\s\n]+constitute[\s\n]+consent[\s\n]+to[\s\n]+PM,[\s\n]+LE[\s\n]+or[\s\n]+CI[\s\n]+investigative[\s\n]+searching[\s\n]+or[\s\n]+monitoring[\s\n]+of[\s\n]+the[\s\n]+content[\s\n]+of[\s\n]+privileged[\s\n]+communications,[\s\n]+or[\s\n]+work[\s\n]+product,[\s\n]+related[\s\n]+to[\s\n]+personal[\s\n]+representation[\s\n]+or[\s\n]+services[\s\n]+by[\s\n]+attorneys,[\s\n]+psychotherapists,[\s\n]+or[\s\n]+clergy,[\s\n]+and[\s\n]+their[\s\n]+assistants.[\s\n]+Such[\s\n]+communications[\s\n]+and[\s\n]+work[\s\n]+product[\s\n]+are[\s\n]+private[\s\n]+and[\s\n]+confidential.[\s\n]+See[\s\n]+User[\s\n]+Agreement[\s\n]+for[\s\n]+details."

# There was a regular-expression matching various banners, needs to be expanded
expanded=$(echo "$login_banner_text" | sed 's/\[\\s\\n\][+*]/ /g;s/\\//g;s/[^-]- /\n\n-/g')
formatted=$(echo "$expanded" | fold -sw 80)

cat <<EOF >/etc/issue
$formatted
EOF

printf "\n" >> /etc/issue


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


#
# Set runtime for net.ipv4.ip_forward
#
/sbin/sysctl -q -n -w net.ipv4.ip_forward=0

#
# If net.ipv4.ip_forward present in /etc/sysctl.conf, change value to "0"
#	else, add "net.ipv4.ip_forward = 0" to /etc/sysctl.conf
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

replace_or_append '/etc/sysctl.conf' '^net.ipv4.ip_forward' "0" 'CCE-80157-1'

sysctl_net_ipv4_conf_all_accept_source_route_value="0"

#
# Set runtime for net.ipv4.conf.all.accept_source_route
#
/sbin/sysctl -q -n -w net.ipv4.conf.all.accept_source_route=$sysctl_net_ipv4_conf_all_accept_source_route_value

#
# If net.ipv4.conf.all.accept_source_route present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv4.conf.all.accept_source_route = value" to /etc/sysctl.conf
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

replace_or_append '/etc/sysctl.conf' '^net.ipv4.conf.all.accept_source_route' "$sysctl_net_ipv4_conf_all_accept_source_route_value" 'CCE-27434-0'

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

sysctl_net_ipv6_conf_all_accept_source_route_value="0"

#
# Set runtime for net.ipv6.conf.all.accept_source_route
#
/sbin/sysctl -q -n -w net.ipv6.conf.all.accept_source_route=$sysctl_net_ipv6_conf_all_accept_source_route_value

#
# If net.ipv6.conf.all.accept_source_route present in /etc/sysctl.conf, change value to appropriate value
#	else, add "net.ipv6.conf.all.accept_source_route = value" to /etc/sysctl.conf
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

replace_or_append '/etc/sysctl.conf' '^net.ipv6.conf.all.accept_source_route' "$sysctl_net_ipv6_conf_all_accept_source_route_value" 'CCE-80179-5'

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

rsyslog_remote_loghost_address="NULL"

if [ "$rsyslog_remote_loghost_address" != "NULL" ]
then

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

    replace_or_append '/etc/rsyslog.conf' '^\*\.\*' "@@$rsyslog_remote_loghost_address" 'CCE-27343-3' '%s %s'
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

var_auditd_space_left_action="email"

grep -q ^space_left_action /etc/audit/auditd.conf && \
  sed -i "s/space_left_action.*/space_left_action = $var_auditd_space_left_action/g" /etc/audit/auditd.conf
if ! [ $? -eq 0 ]; then
    echo "space_left_action = $var_auditd_space_left_action" >> /etc/audit/auditd.conf
fi

var_auditd_action_mail_acct="root"

AUDITCONFIG=/etc/audit/auditd.conf

grep -q ^action_mail_acct $AUDITCONFIG && \
  sed -i 's/^action_mail_acct.*/action_mail_acct = '"$var_auditd_action_mail_acct"'/g' $AUDITCONFIG
if ! [ $? -eq 0 ]; then
  echo "action_mail_acct = $var_auditd_action_mail_acct" >> $AUDITCONFIG
fi

# Traverse all of:
#
# /etc/audit/audit.rules,			(for auditctl case)
# /etc/audit/rules.d/*.rules			(for augenrules case)
#
# files to check if '-f .*' setting is present in that '*.rules' file already.
# If found, delete such occurrence since auditctl(8) manual page instructs the
# '-f 2' rule should be placed as the last rule in the configuration
find /etc/audit /etc/audit/rules.d -maxdepth 1 -type f -name *.rules -exec sed -i '/-e[[:space:]]\+.*/d' {} ';'

# Append '-f 2' requirement at the end of both:
# * /etc/audit/audit.rules file 		(for auditctl case)
# * /etc/audit/rules.d/immutable.rules		(for augenrules case)

for AUDIT_FILE in "/etc/audit/audit.rules" "/etc/audit/rules.d/immutable.rules"
do
	echo '' >> $AUDIT_FILE
	echo '# Set the audit.rules configuration to halt system upon audit failure per security requirements' >> $AUDIT_FILE
	echo '-f 2' >> $AUDIT_FILE
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

fix_audit_watch_rule "auditctl" "/var/run/faillock/" "wa" "logins"
fix_audit_watch_rule "augenrules" "/var/run/faillock/" "wa" "logins"


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

fix_audit_watch_rule "auditctl" "/var/log/lastlog" "wa" "logins"
fix_audit_watch_rule "augenrules" "/var/log/lastlog" "wa" "logins"


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S creat -F exit=-EACCESS.*"
	GROUP="access"
	FULL_RULE="-a always,exit -F arch=$ARCH -S creat -F exit=-EACCESS -F auid>=1000 -F auid!=4294967295 -F key=access"
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

for ARCH in "${RULE_ARCHS[@]}"
do
        PATTERN="-a always,exit -F arch=$ARCH -S creat -F exit=-EPERM.*" 
        GROUP="access"
        FULL_RULE="-a always,exit -F arch=$ARCH -S creat -F exit=-EPRM -F auid>=1000 -F auid!=4294967295 -F key=access"
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


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S open -F exit=-EACCESS.*"
	GROUP="access"
	FULL_RULE="-a always,exit -F arch=$ARCH -S open -F exit=-EACCESS -F auid>=1000 -F auid!=4294967295 -F key=access"
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

for ARCH in "${RULE_ARCHS[@]}"
do
        PATTERN="-a always,exit -F arch=$ARCH -S open -F exit=-EPERM.*" 
        GROUP="access"
        FULL_RULE="-a always,exit -F arch=$ARCH -S open -F exit=-EPRM -F auid>=1000 -F auid!=4294967295 -F key=access"
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


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S openat -F exit=-EACCESS.*"
	GROUP="access"
	FULL_RULE="-a always,exit -F arch=$ARCH -S openat -F exit=-EACCESS -F auid>=1000 -F auid!=4294967295 -F key=access"
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

for ARCH in "${RULE_ARCHS[@]}"
do
        PATTERN="-a always,exit -F arch=$ARCH -S openat -F exit=-EPERM.*" 
        GROUP="access"
        FULL_RULE="-a always,exit -F arch=$ARCH -S openat -F exit=-EPRM -F auid>=1000 -F auid!=4294967295 -F key=access"
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


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S open_by_handle_at -F exit=-EACCESS.*"
	GROUP="access"
	FULL_RULE="-a always,exit -F arch=$ARCH -S open_by_handle_at -F exit=-EACCESS -F auid>=1000 -F auid!=4294967295 -F key=access"
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

for ARCH in "${RULE_ARCHS[@]}"
do
        PATTERN="-a always,exit -F arch=$ARCH -S open_by_handle_at -F exit=-EPERM.*" 
        GROUP="access"
        FULL_RULE="-a always,exit -F arch=$ARCH -S open_by_handle_at -F exit=-EPRM -F auid>=1000 -F auid!=4294967295 -F key=access"
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


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S truncate -F exit=-EACCESS.*"
	GROUP="access"
	FULL_RULE="-a always,exit -F arch=$ARCH -S truncate -F exit=-EACCESS -F auid>=1000 -F auid!=4294967295 -F key=access"
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

for ARCH in "${RULE_ARCHS[@]}"
do
        PATTERN="-a always,exit -F arch=$ARCH -S truncate -F exit=-EPERM.*" 
        GROUP="access"
        FULL_RULE="-a always,exit -F arch=$ARCH -S truncate -F exit=-EPRM -F auid>=1000 -F auid!=4294967295 -F key=access"
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


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S ftruncate -F exit=-EACCESS.*"
	GROUP="access"
	FULL_RULE="-a always,exit -F arch=$ARCH -S ftruncate -F exit=-EACCESS -F auid>=1000 -F auid!=4294967295 -F key=access"
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

for ARCH in "${RULE_ARCHS[@]}"
do
        PATTERN="-a always,exit -F arch=$ARCH -S ftruncate -F exit=-EPERM.*" 
        GROUP="access"
        FULL_RULE="-a always,exit -F arch=$ARCH -S ftruncate -F exit=-EPRM -F auid>=1000 -F auid!=4294967295 -F key=access"
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


PATTERN="-a always,exit -F path=/usr/sbin/semanage.*"
GROUP="privileged"
FULL_RULE="-a always,exit -F path=/usr/sbin/semanage -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged"
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


PATTERN="-a always,exit -F path=/usr/sbin/setsebool.*"
GROUP="privileged"
FULL_RULE="-a always,exit -F path=/usr/sbin/setsebool -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged"
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


PATTERN="-a always,exit -F path=/usr/bin/chcon.*"
GROUP="privileged"
FULL_RULE="-a always,exit -F path=/usr/bin/chcon -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged"
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


PATTERN="-a always,exit -F path=/usr/sbin/restorecon.*"
GROUP="privileged"
FULL_RULE="-a always,exit -F path=/usr/sbin/restorecon -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged"
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


PATTERN="-a always,exit -F path=/usr/bin/passwd.*"
GROUP="privileged"
FULL_RULE="-a always,exit -F path=/usr/bin/passwd -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged"
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


PATTERN="-a always,exit -F path=/usr/bin/unix_chkpwd.*"
GROUP="privileged"
FULL_RULE="-a always,exit -F path=/usr/bin/unix_chkpwd -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged"
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


PATTERN="-a always,exit -F path=/usr/bin/gpasswd.*"
GROUP="privileged"
FULL_RULE="-a always,exit -F path=/usr/bin/gpasswd -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged"
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


PATTERN="-a always,exit -F path=/usr/bin/chage.*"
GROUP="privileged"
FULL_RULE="-a always,exit -F path=/usr/bin/chage -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged"
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


PATTERN="-a always,exit -F path=/usr/bin/userhelper.*"
GROUP="privileged"
FULL_RULE="-a always,exit -F path=/usr/bin/userhelper -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged"
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


PATTERN="-a always,exit -F path=/usr/bin/su.*"
GROUP="privileged"
FULL_RULE="-a always,exit -F path=/usr/bin/su -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged"
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


PATTERN="-a always,exit -F path=/usr/bin/sudo.*"
GROUP="privileged"
FULL_RULE="-a always,exit -F path=/usr/bin/sudo -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged"
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


PATTERN="-a always,exit -F path=/usr/bin/sudoedit.*"
GROUP="privileged"
FULL_RULE="-a always,exit -F path=/usr/bin/sudoedit -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged"
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


PATTERN="-a always,exit -F path=/usr/bin/chsh.*"
GROUP="privileged"
FULL_RULE="-a always,exit -F path=/usr/bin/chsh -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged"
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


PATTERN="-a always,exit -F path=/usr/bin/umount.*"
GROUP="privileged"
FULL_RULE="-a always,exit -F path=/usr/bin/umount -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged"
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


PATTERN="-a always,exit -F path=/usr/sbin/postdrop.*"
GROUP="privileged"
FULL_RULE="-a always,exit -F path=/usr/sbin/postdrop -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged"
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


PATTERN="-a always,exit -F path=/usr/sbin/postqueue.*"
GROUP="privileged"
FULL_RULE="-a always,exit -F path=/usr/sbin/postqueue -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged"
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


PATTERN="-a always,exit -F path=/usr/libexec/openssh/ssh-keysign.*"
GROUP="privileged"
FULL_RULE="-a always,exit -F path=/usr/libexec/openssh/ssh-keysign -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged"
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


PATTERN="-a always,exit -F path=/usr/libexec/pt_chown.*"
GROUP="privileged"
FULL_RULE="-a always,exit -F path=/usr/libexec/pt_chown -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged"
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


PATTERN="-a always,exit -F path=/usr/bin/crontab.*"
GROUP="privileged"
FULL_RULE="-a always,exit -F path=/usr/bin/crontab -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged"
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


PATTERN="-a always,exit -F path=/usr/sbin/pam_timestamp_check.*"
GROUP="privileged"
FULL_RULE="-a always,exit -F path=/usr/sbin/pam_timestamp_check -F perm=x -F auid>=1000 -F auid!=4294967295 -F key=privileged"
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


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S rmdir.*"
	GROUP="delete"
	FULL_RULE="-a always,exit -F arch=$ARCH -S rmdir -F auid>=1000 -F auid!=4294967295 -F key=delete"
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


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S unlink.*"
	GROUP="delete"
	FULL_RULE="-a always,exit -F arch=$ARCH -S unlink -F auid>=1000 -F auid!=4294967295 -F key=delete"
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


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S unlinkat.*"
	GROUP="delete"
	FULL_RULE="-a always,exit -F arch=$ARCH -S unlinkat -F auid>=1000 -F auid!=4294967295 -F key=delete"
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


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S rename.*"
	GROUP="delete"
	FULL_RULE="-a always,exit -F arch=$ARCH -S rename -F auid>=1000 -F auid!=4294967295 -F key=delete"
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


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b32" "b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S renameat.*"
	GROUP="delete"
	FULL_RULE="-a always,exit -F arch=$ARCH -S renameat -F auid>=1000 -F auid!=4294967295 -F key=delete"
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
	PATTERN="-a always,exit -F arch=$ARCH -S init_module \(-F key=\|-k \).*"
	GROUP="modules"
	FULL_RULE="-a always,exit -F arch=$ARCH -S init_module -k modules"
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


# First perform the remediation of the syscall rule
# Retrieve hardware architecture of the underlying system
# Note: 32-bit kernel modules can't be loaded / unloaded on 64-bit kernel =>
#       it's not required on a 64-bit system to check also for the presence
#       of 32-bit's equivalent of the corresponding rule. Therefore for
#       each system it's enought to check presence of system's native rule form.
[ "$(getconf LONG_BIT)" = "32" ] && RULE_ARCHS=("b32") || RULE_ARCHS=("b64")

for ARCH in "${RULE_ARCHS[@]}"
do
	PATTERN="-a always,exit -F arch=$ARCH -S delete_module \(-F key=\|-k \).*"
	GROUP="modules"
	FULL_RULE="-a always,exit -F arch=$ARCH -S delete_module -k modules"
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

fix_audit_watch_rule "auditctl" "/usr/sbin/insmod" "x" "modules"
fix_audit_watch_rule "augenrules" "/usr/sbin/insmod" "x" "modules"


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

fix_audit_watch_rule "auditctl" "/usr/sbin/rmmod" "x" "modules"
fix_audit_watch_rule "augenrules" "/usr/sbin/rmmod" "x" "modules"


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

fix_audit_watch_rule "auditctl" "/usr/sbin/modprobe" "x" "modules"
fix_audit_watch_rule "augenrules" "/usr/sbin/modprobe" "x" "modules"

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

package_command remove telnet-server

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

package_command remove rsh-server

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

package_command remove ypserv

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

package_command remove tftp-server

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

service_command disable kdump
chown root /etc/cron.allow
chgrp root /etc/cron.allow

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

package_command install openssh-server

chmod 0644 /etc/ssh/*.pub

chmod 0640 /etc/ssh/*_key

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

replace_or_append '/etc/ssh/sshd_config' '^GSSAPIAuthentication' 'no' 'CCE-80220-7' '%s %s'

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

replace_or_append '/etc/ssh/sshd_config' '^KerberosAuthentication' 'no' 'CCE-80221-5' '%s %s'

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

replace_or_append '/etc/ssh/sshd_config' '^StrictModes' 'yes' 'CCE-80222-3' '%s %s'

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

replace_or_append '/etc/ssh/sshd_config' '^UsePrivilegeSeparation' 'yes' 'CCE-80223-1' '%s %s'

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

replace_or_append '/etc/ssh/sshd_config' '^Compression' 'no' 'CCE-80224-9' '%s %s'

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

replace_or_append '/etc/ssh/sshd_config' '^PrintLastLog' 'yes' 'CCE-80225-6' '%s %s'

sshd_idle_timeout_value="600"

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

replace_or_append '/etc/ssh/sshd_config' '^IgnoreUserKnownHosts' 'yes' 'CCE-80372-6' '%s %s'

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

replace_or_append '/etc/ssh/sshd_config' '^RhostsRSAAuthentication' 'no' 'CCE-80373-4' '%s %s'
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

sshd_approved_macs="hmac-sha2-512,hmac-sha2-256,hmac-sha1,hmac-sha1-etm@openssh.com,hmac-sha2-256-etm@openssh.com,hmac-sha2-512-etm@openssh.com"

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

replace_or_append '/etc/ssh/sshd_config' '^MACs' "$sshd_approved_macs" 'CCE-27455-5' '%s %s'

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

package_command remove vsftpd
