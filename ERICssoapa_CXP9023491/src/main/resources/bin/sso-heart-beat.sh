#!/bin/bash
############################################################################################################
# Healthcheck - hearbeat script for SSO. This script is configured as a monitored resource by VCS.
# This script will be periodically called by VCS. It will query the health of SSO Jboss through Apache
# tp ensure that PolicyAgent and heimdallr.war are in good working order
#
# This script will also monitor the health of LDAP but will only log if it finds a fault. It will not
# return 1
#
# return values:
#       0 = HEALTHY
#       1 = UNHEALTHY
#
###########################################################################################################

#set -vx

#################################################
#
# File variables
#
#################################################
CURL_DATA="username=notthere&password=nothere"
APACHE_PORT="443"
CURL_PREFIX_HTTP="curl -w %{http_code} -k -L -s --max-time 2 -o /dev/null "
CURL_PREFIX_LDAP="curl -k -L -s --max-time 2 "
HTTP_PROTOCOL="http://"
HTTPS_PROTOCOL="https://"
LDAP_PROTOCOL="ldap://"
LDAP_INSERT="/"
CURL_SUFFIX="/heimdallr/identity/authenticate?$CURL_DATA"
CURL_ISALIVE_SUFFIX="/heimdallr/isAlive.jsp"
JBOSS_PORT="8080"
prg=`basename $0`
# variables for locking
HC_LOCK_DIR=/tmp/sso_sync.lock
HC_LOCK_PID_FILE=${HC_LOCK_DIR}/.hc_pid
GREP=grep
GETENT=/usr/bin/getent
MKDIR=mkdir
ECHO=/bin/echo
CAT=cat
RM=/bin/rm
KILL=/bin/kill
LOCKED=0
LOGGER_TAG="TOR_SSO_HA"
SFS_TIMEOUT=5;#timeout for SFS response in sec

############ temp export for test purposes #################
#export LITP_DE_0_JEE_DE_name="sso"
#export LITP_DE_1_JEE_DE_name="ff"
#export LITP_DE_2_JEE_DE_name="sffso"
#export LITP_DE_3_JEE_DE_name="sderso"
#export LITP_DE_4_JEE_DE_name="saaso"
#export LITP_DE_COUNT=5

############################################################
#
# Logger Functions
#
############################################################
##
## INFORMATION print
##
info()
{
	if [ ${#} -eq 0 ]; then
		while read data; do
			logger -s -t ${LOGGER_TAG} -p user.notice "INFORMATION ( ${SCRIPT_NAME} ): ${data}"
		done
	else
		logger -s -t ${LOGGER_TAG} -p user.notice "INFORMATION ( ${SCRIPT_NAME} ): $@"
	fi
}

##
## ERROR print
##
error()
{
	if [ ${#} -eq 0 ]; then
		while read data; do
			logger -s -t ${LOGGER_TAG} -p user.err "ERROR ( ${SCRIPT_NAME} ): ${data}"
		done
	else
		logger -s -t ${LOGGER_TAG} -p user.err "ERROR ( ${SCRIPT_NAME} ): $@"
	fi
}

##
## WARN print
##
warn()
{
	if [ ${#} -eq 0 ]; then
		while read data; do
			logger -s -t ${LOGGER_TAG} -p user.warning "WARN ( ${SCRIPT_NAME} ): ${data}"
		done
	else
		logger -s -t ${LOGGER_TAG} -p user.warning "WARN ( ${SCRIPT_NAME} ): $@"
	fi
}

#####################################################
#
# Release the lock on the script
#
#########################################################
releaseHCLock() {
# Check for safe HC_LOCK_DIR setting
if ! $ECHO "${HC_LOCK_DIR}" | ${GREP} "^/tmp/" >/dev/null; then
	error "Invalid HC_LOCK_DIR setting: [${HC_LOCK_DIR}]. Lock directory must be created under /tmp\n"
		#exit 1
		exit 0
	fi
# Check lock exists
if [ ! -d "${HC_LOCK_DIR}" ]; then
	#info " No lock to release."
	LOCKED=0
	return 0
fi
local HC_pid=$($CAT ${HC_LOCK_PID_FILE} 2>/dev/null)
if [ -z "${HC_pid}" ]; then
		# Wait a bit
		sleep 5
		local HC_pid=$(${CAT} ${HC_LOCK_PID_FILE} 2>/dev/null)
	fi
# Decide lock is stale if still no pid
if [ -z "${HC_pid}" ]; then
		# Remove stale lock
		[ -d "${HC_LOCK_DIR}" ] && $RM -rf ${HC_LOCK_DIR}
		#info " Removed stale HC lock."
		LOCKED=0
		return 0
	fi
# Release only if this process has the lock
if [ "${HC_pid}" = "$$" ]; then
		# Release the lock
		[ -d "${HC_LOCK_DIR}" ] && $RM -rf ${HC_LOCK_DIR}
		#info " Released HC lock [${HC_LOCK_DIR}]."
		LOCKED=0
		return 0
	fi
# Not locked by this processinfo " This process [$$] tried to release a HC lock but process [$HC_pid] is the lock owner."
LOCKED=1
return 1
}


###########################
#
#
# Exit the script and log a message
#
# Arguments:
#                       int: the exit code
# Return Values:
#                       int: the exit code
#
##########################
function exit_script {

	#info "EXITING SCRIPT and releasing lock, with return code $1"
	releaseHCLock
	exit $1
}

#######################################################################
#
# Log that we have been interrupted and allow exit_script to cleanup
#
########################################################################
function handleInterrupt() {

	error "Script INTERRUPTED, exiting but not forcing failover"
	error "Interrupted pid was:  $$"
	exit_script 0
}

##################################################################
#
# Check for existence of imports
#
###################################################################
##############
# FEATURE ENV
##############
GLOBAL_PROPERTIES=/ericsson/tor/data/global.properties
GLOBAL_PROPERTIES_COPY=/opt/ericsson/sso/etc/global.properties
LOCAL_PROPERTIES=/opt/ericsson/sso/etc/env-vars.conf

# Copy Global Properties
if [ ! -f "${GLOBAL_PROPERTIES_COPY}" ]; then
                info "File ${GLOBAL_PROPERTIES_COPY} does not exist.  Copying ${GLOBAL_PROPERTIES}  to ${GLOBAL_PROPERTIES_COPY}"
                timeout ${SFS_TIMEOUT} cp ${GLOBAL_PROPERTIES}  ${GLOBAL_PROPERTIES_COPY}

                if [ ! -f "${GLOBAL_PROPERTIES_COPY}" ]; then
                   error "Either the SFS does not respond in the specified time (${SFS_TIMEOUT} s) or the ${GLOBAL_PROPERTIES} file does not exist"
                   error "Script cannot continue. Exiting" 
                   exit_script 1
                fi
fi


if [ ! -f "${LOCAL_PROPERTIES}" ]; then
	error "File ${LOCAL_PROPERTIES} does not exist. Script cannot continue. Possible problem with RPM installation. Exiting"
	exit_script 1
fi

. ${GLOBAL_PROPERTIES_COPY}
. ${LOCAL_PROPERTIES}


#####################################################
#
# Attempt to obtain an exclusive lock on this file, it should only ever
# be executed by one process at a time
#
#########################################################
getHCLock() {
# Local vars local HC_pid
# Check for safe HC_LOCK_DIR setting
if ! $ECHO "${HC_LOCK_DIR}" | ${GREP} "^/tmp/" >/dev/null; then
	#$ECHO "Error: Invalid HC_LOCK_DIR setting: [${HC_LOCK_DIR}]. Lock directory must be created under /tmp\n"
		#exit 1
		exit 0
	fi

	if [ ! -d "${HC_LOCK_DIR}" ]; then

		$MKDIR -p ${HC_LOCK_DIR} 2> /dev/null

	fi

# Lock FAILED - check for stale lockinfo " HC lock FAILED; checking for stale lock ..."
MY_HC_pid=($$)
HC_pid=`(${CAT} ${HC_LOCK_PID_FILE} > /dev/null 2>&1)`
#info " Lock PID file contains: [${HC_pid}]"

if [ -n "${HC_pid}" ]; then
	#$ECHO "Current pid ${HC_pid} , my pid ${MY_HC_pid} "
	if [ "${MY_HC_pid}" ==  "${HC_pid}" ]; then

		$ECHO ${MY_HC_pid} > ${HC_LOCK_PID_FILE}
		#$ECHO "I locked the file"
		LOCKED=0
	else
		 # Wait a bit before assuming stale lock i.e. a script
		 # was interrupted after acquiring the lock but before
		 # it could install the interupt handler to remove it
		 sleep 5
		fi
# Check for active process with discovered pid
$KILL -0 ${HC_pid} 2> /dev/null
if [ "${?}" = "0" ]; then
				# Another active process already has the lock
				$ECHO "Error: Another process with PID [${HC_pid}] has locked this admin function. Please try later.\n"
				LOCKED=1
				return 1
			else
				# Remove stale lock
				[ -d "${HC_LOCK_DIR}" ] && $RM -rf ${HC_LOCK_PID_FILE}
				#info " Removed stale HC lock."
				$ECHO "${MY_HC_pid}" > ${HC_LOCK_PID_FILE}
				LOCKED=0
			fi

		else
			#info "My value set in current lock file, locking"
			$ECHO "${MY_HC_pid}" > ${HC_LOCK_PID_FILE}
			LOCKED=0
		fi

# There is no active process with this pid - remove stale lock [ -d "${HC_LOCK_DIR}" ] && $RM -rf ${HC_LOCK_DIR}info " No active process with PID [$HC_pid]; Removed stale HC lock."
# Try to lock again getHCLock
}





################################################################
#
# Before we go any further, attempt to obtain an exclusive lock
#
################################################################
getHCLock

if [ "$LOCKED" == 0 ];
	then
	${ECHO} "" > /dev/null
	#info "Exclusive lock obtained on script, continuing...."
else
	error "This Script appears to be locked by another process, exiting "
	error "Exiting with return code 1"
	exit_script 1
fi



#####################################################################################################
# This function check the health of the current SC instance i.e. the instance this script resides on
# It takes one paramter, an integer, indicating how many layers of SSO it should check
#
# As OpenAM does npt facilitate querying of LDAP health thru OpenAm LDAP is queried separately(it returns a generic
# error if LDAP is uncontactable)
#
# Original Healthcheck script provided the ability to pick whether you query JBOSS directly or thru apache
# The option is left here however it will always be querired through Apache
#  arguments:
#           int 2: Query SSO thru Apache (2 layers of SSO)
#           int 1:  Query SSO thru Jboss (1 layers of SSO,bypassing Apache)
#
#####################################################################################################
function checkThisSC {


#info "Checking SSO status on ${HOSTNAME} "

$GETENT hosts SC-1 | $GREP `hostname` > /dev/null
local THIS_JBOSS="sso.${UI_PRES_SERVER}"

# Check Apache / SSO JBoss

# Directly query JBoss
if  [ "$1" -eq 1 ]; then

	CURL_SSO=${CURL_PREFIX_HTTP}${HTTP_PROTOCOL}${THIS_JBOSS}:${JBOSS_PORT}${CURL_ISALIVE_SUFFIX}
	#info "HTTP target is: $CURL_SSO"

	if [ `$CURL_SSO` -ne "200" ]; then
		error "SSO Heartbeat of ${HOSTNAME} : FAILED, exiting..."
		exit_script 1
	fi


# Query JBoss thru Apache and confirm LDAP
elif [ "$1" -eq 2 ];then

	###############################################
	##
	## TORFTUISSO-904,TORFTUISSO-907
	##
	## ealemca Thu, Feb 20, 2014  4:06:23 PM
	##
	## Fix to stop HA failover/flip-flopping until
	## Core Middleware/LITP solution becomes stable
	##
	###############################################
	exit_script 0

	# Check LDAP
	#info "Checking LDAP connections from ${HOSTNAME}"
	CURL_LDAP_1=${CURL_PREFIX_LDAP}${LDAP_PROTOCOL}${COM_INF_LDAP_HOST_1}${LDAP_INSERT}${COM_INF_LDAP_ROOT_SUFFIX}
	CURL_LDAP_2=${CURL_PREFIX_LDAP}${LDAP_PROTOCOL}${COM_INF_LDAP_HOST_2}${LDAP_INSERT}${COM_INF_LDAP_ROOT_SUFFIX}

	#info "LDAP1 target is $CURL_LDAP_1"
	#info "LDAP2 target is $CURL_LDAP_2"

	# Check LDAP 1
	if ! $CURL_LDAP_1 | grep "${COM_INF_LDAP_ROOT_SUFFIX}"; then
		warn "Heartbeat of LDAP ${COM_INF_LDAP_HOST_1} from ${HOSTNAME}:  FAILED"
		warn "Script will not exit, logged WARNING and continuing"
	fi

	# Check LDAP 2
	if ! $CURL_LDAP_2 | grep "${COM_INF_LDAP_ROOT_SUFFIX}"; then
		warn "Heartbeat of LDAP ${COM_INF_LDAP_HOST_1} from ${HOSTNAME}:  FAILED"
		warn "Script will not exit, logged WARNING and continuing"
	fi

	# Check Apache/JBoss
	CURL_SSO=${CURL_PREFIX_HTTP}${HTTPS_PROTOCOL}${UI_PRES_SERVER}:${APACHE_PORT}${CURL_ISALIVE_SUFFIX}
	#info "HTTPS target is: $CURL_SSO"

	# Check CURL _max_checks_ times to make sure it works
	local _counter_=0
	local _max_checks_=3

	while [ $_counter_ -lt $_max_checks_ ]; do
		local _curl_result_=`$CURL_SSO`
		if [ $_curl_result_ = "200" ]; then
			break
		else
			warn "SSO Heartbeat of ${HOSTNAME} : FAILED. Performing re-check..."
			sleep 2
		fi;
		(( _counter_ +=1 ))
	done

	# Exit with failure if CURL failed _max_checks_ times
	if [ $_counter_ = $_max_checks_ ]; then
		error "SSO Heartbeat of ${HOSTNAME} : FAILED ${_max_checks_} checks, exiting with failure..."
		exit_script 1
	fi
else

	error "SSO Heartbeat of ${HOSTNAME} FAILED, illegal arguments, unknown error, returning 1"
	exit_script 1

fi;
}



##################################################################################################
# Executed if the script is on the 'active' SC
# arguments:
#           int 2: Query SSO thru Apache (2 layers of SSO)
#           int 1:  Query SSO  Jboss only
# 1 indicates PROBE functionality and only the JBoss will be directly queried. This is needed fo install, 
# upgrade and restart functionality where we need to ensure JBoss is up nd running before apache
# 2 indicates that both Apache and Jboss should be queried. This indcates normal operation High Availability check
###################################################################################################
function heartBeat() {

	#info "Heartbeat check of ${HOSTNAME} triggered with a parameter of $1"
	checkThisSC $1

}
# configure trap
trap 'handleInterrupt' HUP INT QUIT TERM

# brains of the operation
if [ $# -eq 0 ]
	then
	error "No arguments supplied. Script expects integer parameter of 1 or 2, exiting"
	exit_script 1
elif [ $1 -eq 1 ]
	then
	#info "Argument passed $1. PROBE functionality."
	heartBeat 1
elif [ $1 -eq 2 ]
	then
	#info "Argument passed $1. HA functionality"
	heartBeat 2
fi


# to be sure to be sure
#info "All SSO Upgrade Health Checks PASSED"
exit_script 0
