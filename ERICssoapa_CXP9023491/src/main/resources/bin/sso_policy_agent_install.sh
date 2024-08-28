#!/bin/bash

######################################################
#
# Install policy agent on Apache
#
#######################################################



# UTILITIES
AMF_ADM=/usr/bin/amf-adm
AMF_FIND=/usr/bin/amf-find
AMF_STATE=/usr/bin/amf-state
AWK=/bin/awk
BASENAME=/bin/basename
CAT=/bin/cat
CHCON=/usr/bin/chcon
CHMOD=/bin/chmod
CP=/bin/cp
ECHO="echo -e"
FIND=/bin/find
GETSEBOOL=/usr/sbin/getsebool
GREP=/bin/grep
HEAD=/usr/bin/head
ID=/usr/bin/id
MKDIR=/bin/mkdir
MV=/bin/mv
PS=/bin/ps
RESTORECON=/sbin/restorecon
RM=/bin/rm
SED=/bin/sed
SEMANAGE=/usr/sbin/semanage
SETSEBOOL=/usr/sbin/setsebool


SLEEP_INTERVAL=15

CERTUTIL_CERT_ALIAS="sso-server"
HTTPD_SERVICE_INSTANCE=`${AMF_FIND} si | ${GREP} -i 'httpd\|Apache'`
SCRIPT_NAME=`${BASENAME} ${0}`
SYSCONFIG_FILE=/etc/sysconfig/httpd
APACHE_CERT_DIR=/ericsson/tor/data/certificates/sso
APACHE_CERT_PREFIX=ssoserverapache
PKI_CERT_DIR=/etc/pki/tls/certs
PKI_KEY_DIR=/etc/pki/tls/private
APACHE_CERT=${PKI_CERT_DIR}/${APACHE_CERT_PREFIX}.crt
APACHE_KEY=${PKI_KEY_DIR}/${APACHE_CERT_PREFIX}.key
JBOSS_CERT=${APACHE_CERT_DIR}/ssoserverjboss.crt
GLOBAL_PROPERTIES=/ericsson/tor/data/global.properties
LOCAL_PROPERTIES=/opt/ericsson/sso/etc/env-vars.conf
SSO_CONF_DIR=/opt/ericsson/sso/etc/
NEW_APACHE_CERT=${APACHE_CERT_DIR}/${APACHE_CERT_PREFIX}.crt
NEW_APACHE_KEY=${APACHE_CERT_DIR}/${APACHE_CERT_PREFIX}.key
SSO_APACHE_CONF=40_ftsso_main.conf
UI_APACHE_CONF=20_ftui_main.conf
DEFAULT_SSL_CONF=ssl.conf
APACHE_HOME=/etc/httpd
RESPONSE_FILE=/tmp/policy-agent.conf

# Override config files for testing if needed - assumes
# ${1} is GLOBAL_PROPERTIES and ${2} is LOCAL_PROPERTIES
if [ ! "x${1}" = "x" -a ! "x${2}" = "x" ]; then
	echo "Executing ${SCRIPT_NAME} in test mode"
	GLOBAL_PROPERTIES="${1}"
	LOCAL_PROPERTIES="${2}"
	. ${GLOBAL_PROPERTIES}
	. ${LOCAL_PROPERTIES}
fi

FILES_TO_CHECK="${JBOSS_CERT} ${GLOBAL_PROPERTIES} ${LOCAL_PROPERTIES} ${SYSCONFIG_FILE}"

##
## INFORMATION print
##
info()
{
	if [ ${#} -eq 0 ]; then
		while read data; do
			logger -s -t TOR_SSO_PA -p user.notice "INFORMATION ( ${SCRIPT_NAME} ): ${data}"
		done
	else
		logger -s -t TOR_SSO_PA -p user.notice "INFORMATION ( ${SCRIPT_NAME} ): $@"
	fi
}

## ERROR print
##
error()
{
	if [ ${#} -eq 0 ]; then
		while read data; do
			logger -s -t TOR_SSO_PA -p user.err "ERROR ( ${SCRIPT_NAME} ): ${data}"
		done
	else
		logger -s -t TOR_SSO_PA -p user.err "ERROR ( ${SCRIPT_NAME} ): $@"
	fi
}

##
## Check if all the necessary files exist
##
check_files_exist()
{
	local L_FILES_NOT_THERE=""

	for file in ${FILES_TO_CHECK}; do
		if [ ! -f "${file}" ]; then
			error "${file} does not exist."
			L_FILES_NOT_THERE="y"
		fi
	done

	if [ ! -z "${L_FILES_NOT_THERE}" ]; then
		error "Files are missing that are necessary for script execution. Cannot continue, exiting"
		exit 1
	fi
}

##
## Clean up function to remove temporary files
##
cleanup ()
{
	for i in ${TMP_FILES}; do
		#remove_file ${i}
		info "No cleanup needed"
	done
}

##
## Exit gracefully so as not to break flow
##
graceful_exit ()
{
	[ "${#}" -gt 1 -a "${1}" -eq 0 ] && info "${2}"
	[ "${#}" -gt 1 -a "${1}" -gt 0 ] && error "${2}"
	cleanup
	exit ${1}
}

check_files_exist

. ${GLOBAL_PROPERTIES}
. ${LOCAL_PROPERTIES}

AGENT_HOME=$SSO_HOME/web_agents/apache22_agent
SSO_CERTDB=$AGENT_HOME/certs

##
## Apache configuration for SSO
##
HTTPD_CONF_HOME=$APACHE_HOME/conf
HTTPD_CONF_D_HOME=$APACHE_HOME/conf.d
POLICY_AGENT_HTTPD_CONF_FILE=$SSO_HOME/etc/$SSO_APACHE_CONF


## Functions to start and stop apache
##
stop_httpd()
{

 	${AMF_ADM} lock $HTTPD_SERVICE_INSTANCE > /dev/null 2>&1
	info "Pausing for ${SLEEP_INTERVAL} seconds to allow Apache to go offline..."
	sleep ${SLEEP_INTERVAL}
}

start_httpd()
{
 	${AMF_ADM} unlock $HTTPD_SERVICE_INSTANCE > /dev/null 2>&1
	info "Pausing for ${SLEEP_INTERVAL} seconds to allow Apache to go online..."
	sleep ${SLEEP_INTERVAL}
}

# Function to check that Apache is correctly defined as httpd
check_httpd_definition()
{
	# Make sure that the Apache SG and SI are called httpd
	local _apache_name_=$(${AMF_STATE} si all | ${GREP} -i 'httpd\|Apache' | ${AWK} -F= '{print $2}' | ${AWK} -F_ '{print $1}')
	if [[ ${_apache_name_} == "httpd" ]]; then
		info "The Service Instance for Apache is called '${_apache_name_}', continuing with installation of Policy Agent...."
	else
		error "The Service Instance for Apache is called '${_apache_name_}'. It should be called 'httpd'. Cancelling installation of Policy Agent...."
		exit 1
	fi

	return 0
}


# Function to check if Apache is running and stop it by any means necessary
check_if_httpd_running()
{
	if ${AMF_STATE} su all | ${GREP} -i 'httpd\|Apache' -A 4 | ${GREP} -w INSTANTIATED > /dev/null 2>&1; then
		local res=`${AMF_STATE} su all | ${GREP} -i 'httpd\|Apache' -A 4 | ${GREP} -w INSTANTIATED`
		info "Apache Webserver is running on a server in the cluster, this needs to be stopped to install policy agent"
		info "This command was used: ${AMF_STATE} su all | ${GREP} -i 'httpd\|Apache' -A 4 | ${GREP} -w INSTANTIATED"
		info "Result was $res"
		info "Here is the full output of ${AMF_STATE} su all | ${GREP} -i 'httpd\|Apache' -A 4"
		${AMF_STATE} su all | ${GREP} -i 'httpd\|Apache' -A 4 | info
		# stop_httpd
	else
		# Add text for CMW
		info "Apache is already offline according to CMW, continuing with installation of Policy Agent...."
	fi

	# Check if there are httpd processes running and get the root pid
	
	# Candidate replacement command for finding rogue httpd process
	#local _httpd_root_process_=$( ${PS} -ef | ${AWK} '/^root/ && /httpd$/ && !/rpm/ {print $2}' )

	local _httpd_root_process_=$( ${PS} -ef | ${AWK} '/^root/ && /httpd$/ && !/rpm/ {print $2}' )
	info "Found httpd process $_httpd_root_process_"
	info "Full output of ${PS} -ef | ${GREP} [h]ttpd:"
	${PS} -ef | ${GREP} [h]ttpd | info
	if [[ -n ${_httpd_root_process_} ]]; then
		# Make sure that Apache is not running on this server via a Linux command, contrary to what CMW says
		# I have seen before that apache can be online even though 'service' command is not aware.
		#info "Apache is online on this server even though it is offline according to CMW. Attempting to offline...."
		info "There is some apache process running that our script has found using this command:"
		info "${PS} -ef | ${AWK} '/^root/ && /httpd$/ && !/rpm/ {print $2}'"
		if service httpd status > /dev/null 2>&1; then
			info "Output of 'service httpd status':"
			service httpd status | info
			#service httpd stop > /dev/null 2>&1
			# Check if the httpd pid still exists
			info "Checking again for httpd process"
			_httpd_root_process_=$( ${PS} -ef | ${AWK} '/^root/ && /httpd$/ && !/rpm/ {print $2}' )
			info "Found httpd process $_httpd_root_process_"
			info "Full output of ${PS} -ef | ${GREP} httpd:"
			${PS} -ef | ${GREP} httpd | info
			if [[ -n ${_httpd_root_process_} ]]; then
				info "Found a httpd process using previous command, ignoring..."
				#kill ${_httpd_root_process_}
			fi
		else
			# Since service is not aware of Apache, we need to kill it
			info "Apache confirmed to be offline."
			#kill ${_httpd_root_process_}
		fi
	fi

	return 0
}


##
## Remove the password file used during installation
##
remove_password_file(){


	if [ -f ${SSO_CONF_DIR}/agent-access.bin ]; then
		info "Encrypting and cleaning passwords"
		${RM} -f ${SSO_CONF_DIR}/agent-access.bin
	
	else
		info "No passwords to clean up"
	fi
	
}

update_web_server_config()
{

	#############################################
	#
	# Modify the httpd config file at $POLICY_AGENT_HTTPD_CONF_FILE
	#
	#############################################
	#
	# Find the placeholder string "placeholder.module" and replace it with the policy
	# agent configuration file loaded by Apache httpd
	POLICY_AGENT_CONF_INCLUDE=`${GREP} -i "^include.*dsame\.conf$" $HTTPD_CONF_HOME/httpd.conf`

	info "Copying template file to ${HTTPD_CONF_D_HOME}"
	# Copy the template file into the httpd config directory
	${CP} -f $POLICY_AGENT_HTTPD_CONF_FILE $HTTPD_CONF_D_HOME/

	# Use the output of the "hostname" command as the virtual host
	# (same as UI config)
	APACHE_VHOST=${UI_PRES_SERVER}

	CURRENT_AGENT_DIR=`${AWK} '/Agent_/{print $2}' $AGENT_HOME/data/.amAgentLookup`

	info "Customizing template file $HTTPD_CONF_D_HOME/$SSO_APACHE_CONF"
	# N.B. seperator is '|' (pipe) - easier to read patterns when there are '/' characters in the string
	${SED} -i "s|${PLACEHOLDER_POLICY_AGENT_MODULES}|${CURRENT_AGENT_DIR}|g;\
	s|${PLACEHOLDER_VIRTUAL_HOSTNAME}|${APACHE_VHOST}|g;\
	s|${PLACEHOLDER_VIRTUAL_PORT}|${AGENT_PORT}|g;\
	s|${PLACEHOLDER_LOGIN_REWRITE_RULE}|${OPENAM_SERVER_URL_SECURE}/${SSO_DEPLOYMENT_NAME}/UI/Login|g;\
	s|${PLACEHOLDER_LOGIN_PROXY_RULE}|${OPENAM_SERVER_URL_SECURE}/${SSO_DEPLOYMENT_NAME}/UI/Login|g;\
	s|${PLACEHOLDER_LOGOUT_REWRITE_RULE}|${OPENAM_SERVER_URL_SECURE}/${SSO_DEPLOYMENT_NAME}/UI/Logout|g;\
	s|${PLACEHOLDER_LOGOUT_PROXY_RULE}|${OPENAM_SERVER_URL_SECURE}/${SSO_DEPLOYMENT_NAME}/UI/Logout|g;\
	s|${PLACEHOLDER_HEARTBEAT_JBOSS}|${SSO_HEARTBEAT_JBOSS}|g;\
	s|${PLACEHOLDER_HEARTBEAT_LDAP}|${SSO_HEARTBEAT_LDAP}|g;\
	s|${PLACEHOLDER_OPENAM_LANDING}|${SSO_LANDING_PAGE}|g" $HTTPD_CONF_D_HOME/$SSO_APACHE_CONF\
	 || error "Could not customize template file ${POLICY_AGENT_HTTPD_CONF_FILE}"

	# Replace the UI JBoss IP address placeholder - this should be entered
	# in a global properties file
	# ${SED} -i "s|${PLACEHOLDER_UI_JBOSS_IP}|${UI_JBOSS_IP}|g" $POLICY_AGENT_HTTPD_CONF_FILE

	# Check for file /etc/httpd/conf.d/20_ftui_main.conf. If
	# found, rename it with a ".OFF" extension
	if [ -f $HTTPD_CONF_D_HOME/$UI_APACHE_CONF ]; then
		info "Disabling existing UI httpd configuration"
		${MV} $HTTPD_CONF_D_HOME/$UI_APACHE_CONF $HTTPD_CONF_D_HOME/$UI_APACHE_CONF.OFF
	fi

	# Check for file $HTTPD_CONF_D_HOME/${DEFAULT_SSL_CONF}. If
	# found, rename it with a ".OFF" extension
	if [ -f $HTTPD_CONF_D_HOME/${DEFAULT_SSL_CONF} ]; then
		info "Disabling default SSL configuration"
		${MV} $HTTPD_CONF_D_HOME/${DEFAULT_SSL_CONF} $HTTPD_CONF_D_HOME/${DEFAULT_SSL_CONF}.OFF
	fi

	# Restore the original httpd.conf (from any of the backups)
	info "Restoring original httpd.conf"
	HTTPD_CONF_ORIG=`${FIND} $HTTPD_CONF_HOME -type f -name "httpd.conf-preAmAgent-*" | ${HEAD} -1`
	[[ -f $HTTPD_CONF_ORIG ]] && ${MV} $HTTPD_CONF_ORIG $HTTPD_CONF_HOME/httpd.conf

	# Disable certificate checking by Policy Agent
	info "Modifiying certificate validation in $AGENT_HOME/$CURRENT_AGENT_DIR/config/OpenSSOAgentBootstrap.properties"
	${SED} -i "/com.sun.identity.agents.config.trust.server.certs\ =\ false/ s|false|true|g" $AGENT_HOME/$CURRENT_AGENT_DIR/config/OpenSSOAgentBootstrap.properties

}

install_policy_agent()
{

	# Check Apache defined correctly
	#check_httpd_definition

	# ############## Ensure the Apache is shutdown ######################
	# Check if Apache is running on cluster
	check_if_httpd_running

	# install the policy agent using parameters defined in $RESPONSE_FILE
	# script assumes that webagent will be unzipped to /opt/ericsson/sso
	info "Policy Agent response file location: $RESPONSE_FILE"
	
	# For testing
	
cat << EOF > $RESPONSE_FILE
CONFIG_DIR= $HTTPD_CONF_HOME
AM_SERVER_URL= $OPENAM_SERVER_URL_SECURE/$SSO_DEPLOYMENT_NAME
AGENT_URL= $AGENT_SERVER_URL
AGENT_PROFILE_NAME= $SSO_AGENT_NAME
AGENT_PASSWORD_FILE= $SSO_AGENT_ACCESS_FILE
EOF


	# We have to pretend that we have already installed an agent, therefore
	# we will not be prompted to agree to the license agreement
	info "Auto-agreeing to license"

	# Make sure that the USER env variable is set, otherwise, set it ourselves
	if [[ -n ${USER} ]]; then
		echo $USER=`date +"%m/%d/%Y %H\:%M\:%S"` IST > $AGENT_HOME/data/license.log
	else
		USER=$($ID -un)
		echo $USER=`date +"%m/%d/%Y %H\:%M\:%S"` IST > $AGENT_HOME/data/license.log
	fi

	if [ $? -ne 0 ]; then
		error "Problem with accepting the license. Policy Agent installation cannot continue."
		error "Try running this command: echo $USER=`date +"%m/%d/%Y %H\:%M\:%S %Z"` > $AGENT_HOME/data/license.log and running ${SCRIPT_NAME} again"
		exit 1
	fi

	#
	# TODO: change the template file $AGENT_HOME/$CURRENT_AGENT_DIR/config/OpenSSOAgentBootstrap.template?
	# Any other realm being created would need to go and change the bootstrap file anyway
	#

	# The main command
	#
	info "Proceeding to install Policy Agent..."

	if [ ! "x${1}" = "x" -a ! "x${2}" = "x" ]; then
		# Need to check if we are on cygwin or not
		if cygcheck -V > /dev/null 2>&1; then
			${SED} -i "/CONFIG_DIR=/ s|.*CONFIG_DIR.*|CONFIG_DIR= $( cygpath -pm ${HTTPD_CONF_HOME} )|g" $RESPONSE_FILE
			${SED} -i "/AGENT_PASSWORD_FILE=/ s|.*AGENT_PASSWORD_FILE.*|AGENT_PASSWORD_FILE= $( cygpath -pm ${SSO_AGENT_ACCESS_FILE} )|g" $RESPONSE_FILE
			echo "RESPONSE_FILE:"
			cat ${RESPONSE_FILE}
			AGENT_HOME_TMP="${AGENT_HOME}"
			AGENT_HOME=$( cygpath -pw  $SSO_HOME/web_agents/apache22_agent ) \
			bash -x $SSO_HOME/web_agents/apache22_agent/bin/agentadmin --install --debug --useResponse $( cygpath -pw $RESPONSE_FILE )
			AGENT_HOME=${AGENT_HOME_TMP}
		else
			bash -x $SSO_HOME/web_agents/apache22_agent/bin/agentadmin --install --debug --useResponse $RESPONSE_FILE
		fi
	else
		$SSO_HOME/web_agents/apache22_agent/bin/agentadmin --install --useResponse $RESPONSE_FILE | info
	fi

	# Get the name of the latest Agent_ install directory, in case
	# there was a failed installation earlier
	CURRENT_AGENT_DIR=`${AWK} '/Agent_/{print $2}' $AGENT_HOME/data/.amAgentLookup`

	if [ -f $AGENT_HOME/$CURRENT_AGENT_DIR/config/dsame.conf ]; then
		info "Policy Agent installation has been successful."
	else
		error "Problem with Policy Agent installation. Check $AGENT_HOME/installer-logs/debug/Agent.log for errors."
		exit 1
	fi


	# Remove the temp options file
	info "Removing Policy Agent response file"
	${RM} -f ${RESPONSE_FILE}

	#######################################################
	#
	# SELinux configuration - httpd has new modules to load
	# from a non /etc/httpd/modules directory
	#
	#######################################################

	# Change the security context of the modules
	info "SELinux: Changing security context of $AGENT_HOME/lib/"

	${SEMANAGE} fcontext -a -s system_u -t httpd_modules_t "$AGENT_HOME/lib(/.*)?"
	${RESTORECON} -R $AGENT_HOME/lib | info

	# Change the security context for the config files
	info "SELinux: Changing security context of $AGENT_HOME/$CURRENT_AGENT_DIR/config/"

	${SEMANAGE} fcontext -a -s system_u -t httpd_config_t "$AGENT_HOME/$CURRENT_AGENT_DIR/config(/.*)?"
	${RESTORECON} -R $AGENT_HOME/$CURRENT_AGENT_DIR/config | info

	# Change the security context for the log files
	info "SELinux: Changing security context of $AGENT_HOME/$CURRENT_AGENT_DIR/logs"

	${SEMANAGE} fcontext -a -t httpd_log_t "$AGENT_HOME/$CURRENT_AGENT_DIR/logs(/.*)?"
	${RESTORECON} -R $AGENT_HOME/$CURRENT_AGENT_DIR/logs | info

	# Change the security context for the certificates and keys
	# info "SELinux: Changing security context of keys and certs in ${APACHE_CERT_DIR}"
	# for cert_file in ${APACHE_CERT_DIR}/{*.key,*.crt}; do
	# 	${SEMANAGE} fcontext -a -t cert_t ${cert_file}
	# done
	# ${RESTORECON} -R ${APACHE_CERT_DIR} | info

	# Check if httpd can make requests (UI rpm also sets this)

	if ${GETSEBOOL} httpd_can_network_connect | ${GREP} off$; then
		info "SELinux: Allowing httpd to make requests"
		${SETSEBOOL} -P httpd_can_network_connect true
	fi


	##################################################
	#
	# Modify the properties file to point to our Realm
	# and to configure the Policy Agent for SSL
	#
	##################################################

	# Remove existing additions from ${SYSCONFIG_FILE}
	for pattern in "LD_LIBRARY_PATH_64" "NSS_STRICT_NOFORK" "NSS_STRICT_SHUTDOWN"; do
		${GREP} -q ${pattern} ${SYSCONFIG_FILE} > /dev/null 2>&1
		if [ ${?} -eq 0 ]; then
			${SED} -i "/${pattern}/d" ${SYSCONFIG_FILE}
		fi
	done

	# Edit ${SYSCONFIG_FILE}
	${ECHO} 'export NSS_STRICT_NOFORK="DISABLED"\nexport NSS_STRICT_SHUTDOWN=""' >> ${SYSCONFIG_FILE}
	${ECHO} "export LD_LIBRARY_PATH_64=\$LD_LIBRARY_PATH_64:/etc/httpd/modules:${AGENT_HOME}/lib" >> ${SYSCONFIG_FILE}

	info "Editing ${SYSCONFIG_FILE} to set Apache to worker mode"
	${CAT} ${SYSCONFIG_FILE} | ${AWK} '{ if ( match( $0, "#HTTPD=/usr/sbin/httpd.worker") > 0){ \
			print ( substr( $0, 2))
		}
		else {
		        print $0
		}
	}' > /var/tmp/httpd.bkup

        ${MV} /var/tmp/httpd.bkup ${SYSCONFIG_FILE}

	# Create the certificate database using certutil
	if [ -d ${SSO_CERTDB} ]; then
		info "Existing certificate database detected, removing"
		${RM} -rf ${SSO_CERTDB}
	fi

	info "Creating certificate database for Policy Agent at ${SSO_CERTDB}"
	${MKDIR} -p ${SSO_CERTDB}
	${AGENT_HOME}/bin/certutil -N -d ${SSO_CERTDB} -f ${SSO_CERTDB_ACCESS_FILE}
	info "Inserting certificate into ${SSO_CERTDB}"
	${AGENT_HOME}/bin/certutil -A -n ${CERTUTIL_CERT_ALIAS} -t "P,P,P" -d ${SSO_CERTDB} -i ${JBOSS_CERT}
	${AGENT_HOME}/bin/certutil -d ${SSO_CERTDB} -L | ${GREP} ${CERTUTIL_CERT_ALIAS} > /dev/null 2>&1
	[ ${?} -eq 0 ] && info "Certificate imported successfully" \
	|| graceful_exit 1 "Could not import certificate at ${JBOSS_CERT} into certificate database at ${SSO_CERTDB}"

	# Modify $AGENT_HOME/$CURRENT_AGENT_DIR/config/OpenSSOAgentBootstrap.properties
	#
	# include ${REALM} substitution here also
	info "Adding SSL configuration to $AGENT_HOME/$CURRENT_AGENT_DIR/config/OpenSSOAgentBootstrap.properties"
	${SED} -i "/com.sun.identity.agents.config.organization.name\ =\ \/$/ s|\ /$|\ /${REALM_NAME}|g;\
	/com.sun.identity.agents.config.sslcert.dir\ =\ $/ s|$|${SSO_CERTDB}|g;\
	/com.sun.identity.agents.config.certdb.password\ =\ $/ s|$|` cat ${SSO_CERTDB_ACCESS_FILE} `|g;\
	/com.sun.identity.agents.config.certificate.alias\ =\ $/ s|$|${CERTUTIL_CERT_ALIAS}|g" $AGENT_HOME/$CURRENT_AGENT_DIR/config/OpenSSOAgentBootstrap.properties


	#info "Starting Apache..."
	#start_httpd
	
	

	info "Be aware that Apache may be running on another node ( cluster hostname of this host's peer is $( cat /etc/cluster/nodes/peer/hostname ) )"  
	info "Installation complete"
}

##
## Check SSL configuration and update if needed
##
if [ ! -f ${APACHE_CERT} -o ! -f ${APACHE_KEY} ]; then
	info "Apache certificate or key file not present, copying from shared area"
	${CP} -f ${NEW_APACHE_CERT} ${PKI_CERT_DIR} && \
	${CP} -f ${NEW_APACHE_KEY} ${PKI_KEY_DIR} && \
	${CHMOD} 600 ${APACHE_CERT} ${APACHE_KEY} && \
	info "Certificate and key installed"
fi

CURRENT_AGENT_DIR=`${AWK} '/Agent_/{print $2}' $AGENT_HOME/data/.amAgentLookup`
# if there is Policy Agent is installed do upgrade else do install
if [ ! -f $AGENT_HOME/$CURRENT_AGENT_DIR/config/OpenSSOAgentBootstrap.properties ]; then
	info "No existing policy agent detected, proceeding with installation"
	install_policy_agent ${1} ${2}
fi

info "Updating web server configuration file"
update_web_server_config

info "Securing Policy Agent"
remove_password_file



exit 0

