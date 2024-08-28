#!/bin/bash
##
## Copyright (c) 2011 Ericsson AB, 2010 - 2011.
##
## All Rights Reserved. Reproduction in whole or in part is prohibited
## without the written consent of the copyright owner.
##
## ERICSSON MAKES NO REPRESENTATIONS OR WARRANTIES ABOUT THE
## SUITABILITY OF THE SOFTWARE, EITHER EXPRESS OR IMPLIED, INCLUDING
## BUT NOT LIMITED TO THE IMPLIED WARRANTIES OF MERCHANTABILITY,
## FITNESS FOR A PARTICULAR PURPOSE, OR NON-INFRINGEMENT. ERICSSON
## SHALL NOT BE LIABLE FOR ANY DAMAGES SUFFERED BY LICENSEE AS A
## RESULT OF USING, MODIFYING OR DISTRIBUTING THIS SOFTWARE OR ITS
## DERIVATIVES.
##
##
## Script to refresh the Apache web server certificate configuration
## on a LITP peer node

##
## COMMANDS
##
BASENAME=/bin/basename
CHMOD=/bin/chmod
CP=/bin/cp
DIFF=/usr/bin/diff
GREP=/bin/grep
OPENSSL=/usr/bin/openssl
RM=/bin/rm
WC=/usr/bin/wc
UNIQ=/usr/bin/uniq

##
## PATHS
##
APACHE_CERT_DIR=/etc/pki/tls/certs
APACHE_KEY_DIR=/etc/pki/tls/private
POLICY_AGENT_HOME=/opt/ericsson/sso/web_agents/apache22_agent
TEMP_CERT_DIR=/tmp
TOR_CERTS_DIR=/ericsson/tor/data/certificates/sso

##
## ENVIRONMENT
##
APACHE_CERT_FILE=${APACHE_CERT_DIR}/ssoserverapache.crt
APACHE_KEY_FILE=${APACHE_KEY_DIR}/ssoserverapache.key
CERTUTIL=${POLICY_AGENT_HOME}/bin/certutil
CERTUTIL_DIR=${POLICY_AGENT_HOME}/certs
JBOSS_SERVER_CERT_ALIAS="sso-server"
LOCAL_PROPERTIES=/opt/ericsson/sso/etc/env-vars.conf
LOGGER_TAG="TOR_SSO_SECURITY"
NEW_APACHE_CERT_FILE=${TOR_CERTS_DIR}/ssoserverapache.crt
NEW_APACHE_KEY_FILE=${TOR_CERTS_DIR}/ssoserverapache.key
NEW_JBOSS_CERT_FILE=${TOR_CERTS_DIR}/ssoserverjboss.crt
NEW_JBOSS_KEY_FILE=${TOR_CERTS_DIR}/ssoserverjboss.key
RESTART_REQUIRED=0
SCRIPT_NAME=$( ${BASENAME} ${0} )
TEMP_EXPORTED_OLD_APACHE_CERT_FILE=${TEMP_CERT_DIR}/apache_temp.pem
TEMP_EXPORTED_NEW_APACHE_CERT_FILE=${TEMP_CERT_DIR}/apache_new_temp.pem
TEMP_EXPORTED_OLD_JBOSS_CERT_FILE=${TEMP_CERT_DIR}/jboss_temp.der
TEMP_EXPORTED_NEW_JBOSS_CERT_FILE=${TEMP_CERT_DIR}/jboss_new_temp.der

FILES_TO_CHECK="${LOCAL_PROPERTIES}"
FILES_TO_REMOVE="${TEMP_EXPORTED_OLD_APACHE_CERT_FILE} ${TEMP_EXPORTED_NEW_APACHE_CERT_FILE} ${TEMP_EXPORTED_OLD_JBOSS_CERT_FILE} ${TEMP_EXPORTED_NEW_JBOSS_CERT_FILE}"

##
## FUNCTIONS
##
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

##
## Compare the exported PEM files of two certificates
##
## args: $1 - old cert
##       $2 - new cert
check_apache_certificates_differ()
{
	# Export both certs to PEM fromat and run 'diff'
	# on the two temp files
	${OPENSSL} x509 -in $1 > ${TEMP_EXPORTED_OLD_APACHE_CERT_FILE}
	${OPENSSL} x509 -in $2 > ${TEMP_EXPORTED_NEW_APACHE_CERT_FILE}

	${DIFF}	${TEMP_EXPORTED_OLD_APACHE_CERT_FILE} ${TEMP_EXPORTED_NEW_APACHE_CERT_FILE} > /dev/null 2>&1
	[ ${?} -eq 0 ] && return 0 || return 1
}

##
## Compare the exported DER files of two certificates (one in
## the NSS certificate database)
##
## args: $1 - alias
##       $2 - cert db
##       $3 - new cert file
check_jboss_certificates_differ()
{
	# Check db for alias
	${CERTUTIL} -L -d ${2} -n ${1} > /dev/null 2>&1
	[ ${?} -ne 0 ] && graceful_exit 1 "No certificate with alias ${1} found at ${2}. This is unexpected and the script cannot continue"

	# Export both certs to binary DER fromat and run 'diff'
	# on the two temp files

	# Export cert db certificate
	${CERTUTIL} -L -d ${2} -n ${1} -r > ${TEMP_EXPORTED_OLD_JBOSS_CERT_FILE}
	${OPENSSL} x509 -in ${3} -outform DER > ${TEMP_EXPORTED_NEW_JBOSS_CERT_FILE}

	${DIFF} ${TEMP_EXPORTED_OLD_JBOSS_CERT_FILE} ${TEMP_EXPORTED_NEW_JBOSS_CERT_FILE} > /dev/null 2>&1
	[ ${?} -eq 0 ] && return 0 || return 1
}

##
## Check that a certificate and private key pair match
##
## args: $1 - certificate file path
##       $2 - private key file path
##
check_certificate_and_key_match()
{
	info "Checking certificate ${1} against key ${2}"

	MATCH=$( ( ${OPENSSL} x509 -noout -modulus -in ${1} | ${OPENSSL} md5; \
	${OPENSSL} rsa -noout -modulus -in ${2} | ${OPENSSL} md5 ) | ${UNIQ} | ${WC} -l ) 

	[ ${MATCH} -eq 1 ] && return 0 || return 1
}

##
## Remove a certificate entry from NSS database (with alias
## as a key) and replace with an updated one
##
## args: $1 - alias
##       $2 - certificate file
##       $3 - cert database
##
update_certificate_database()
{
	${CERTUTIL} -L -d ${3} -n ${1} > /dev/null 2>&1
	if [ ${?} -eq 0 ]; then

		info "Deleting certificate with alias ${1} from ${3}"
		${CERTUTIL} -D -d ${3} -n ${1} 
		if [ ${?} -ne 0 ]; then
			warn "Could not delete certificate with alias ${1} from ${3}. Existing certificate will be used instead"
			return 1
		else
			info "Certificate deleted. Adding new certificate"
			${CERTUTIL} -A -d ${3} -n ${1} -t "P,P,P" -i ${2}
			if [ ${?} -eq 0 ]; then
				info "Certificate successfully updated"
			else
				graceful_exit 1 "Could not update certificate, certificate database is now empty and SSO will not function correctly"
			fi
		fi

	else
		info "No certificate with alias ${1} to delete in ${3}"
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

cleanup ()
{
	local L_FILES_NOT_REMOVED=""

	if [ ! -z "${FILES_TO_REMOVE}" ]; then
		info "Removing temporary files"
		for temp_file in ${FILES_TO_REMOVE}; do
			if [ -f ${temp_file} ]; then
				${RM} -f ${temp_file} && info "Removed ${temp_file}" || ${L_FILES_NOT_REMOVED}="${L_FILES_NOT_REMOVED} ${temp_file}"
			fi
		done
	else
		info "No temporary files to remove"
	fi

	[ ! -z ${L_FILES_NOT_REMOVED} ] && info "Some files not removed, not fatal: ${L_FILES_NOT_REMOVED}" || info "Clean up complete"
	
	return 0
}

##
## Exit gracfully so as not to break flow
##
graceful_exit ()
{
	[ "${#}" -gt 1 -a "${1}" -eq 0 ] && info "${2}"
	[ "${#}" -gt 1 -a "${1}" -gt 0 ] && error "${2}"
	cleanup
	exit ${1}
}


##
## EXECUTION
##

if [ -f "${NEW_APACHE_CERT_FILE}" -a -f "${NEW_APACHE_KEY_FILE}" ]; then

	# Check that the old and new certificates differ
	check_apache_certificates_differ ${APACHE_CERT_FILE} ${NEW_APACHE_CERT_FILE}
	if [ ${?} -ne 0 ]; then

		# Check the new certificate key and certificate match
		check_certificate_and_key_match ${NEW_APACHE_CERT_FILE} ${NEW_APACHE_KEY_FILE}
		if [ ${?} -eq 0 ]; then

			# Update the new certificate by copying cert and key to final location
			${CP} -f ${NEW_APACHE_CERT_FILE} ${APACHE_CERT_DIR}
			${CP} -f ${NEW_APACHE_KEY_FILE} ${APACHE_KEY_DIR}

			# Make sure of the permissions
			${CHMOD} 400 ${APACHE_CERT_FILE} ${APACHE_KEY_FILE}

			# User will now have to restart Apache for change to take effect
			RESTART_REQUIRED=1

		else
			warn "Key ${NEW_APACHE_KEY_FILE} does not match certificate ${NEW_APACHE_CERT_FILE}."
			warn "Cannot update this certificate. Existing certificate will be used instead"
		fi

	else
		info "No new certificate at ${NEW_APACHE_CERT_FILE} to update"
	fi

else
	info "Required files ${NEW_APACHE_CERT_FILE} and ${NEW_APACHE_KEY_FILE} are not present"
	info "Cannot update certificate. Existing certificate will be used instead"
fi


if [ -f "${NEW_JBOSS_CERT_FILE}" -a -f "${NEW_JBOSS_KEY_FILE}" ]; then

	# Check that the old and new certificates differ
	check_jboss_certificates_differ ${JBOSS_SERVER_CERT_ALIAS} ${CERTUTIL_DIR} ${NEW_JBOSS_CERT_FILE}
	if [ ${?} -ne 0 ]; then

		# Check the new certificate key and certificate match
		check_certificate_and_key_match ${NEW_JBOSS_CERT_FILE} ${NEW_JBOSS_KEY_FILE}
		if [ ${?} -eq 0 ]; then

			# Update the new certificate by deleting the existing entry in the 
			# certificate database and importing the new one
			update_certificate_database ${JBOSS_SERVER_CERT_ALIAS} ${NEW_JBOSS_CERT_FILE} ${CERTUTIL_DIR}

			# User will now have to restart Apache for change to take effect
			[ ${?} -eq 0 ] && RESTART_REQUIRED=1

		else
			warn "Key ${NEW_JBOSS_KEY_FILE} does not match certificate ${NEW_JBOSS_CERT_FILE}."
			warn "Cannot update this certificate. Existing certificate will be used instead"
		fi

	else
		info "No new certificate at ${NEW_JBOSS_CERT_FILE} to update"
	fi

else
	info "Required files ${NEW_JBOSS_CERT_FILE} and ${NEW_JBOSS_KEY_FILE} are not present"
	info "Cannot update certificate. Existing certificate will be used instead"
fi

if [ ${RESTART_REQUIRED} -ne 0 ]; then
	info "Restart of Apache is required on both nodes before configuration will take effect"
else
	info "No certificates were updated, no restart of Apache is required"
fi

graceful_exit 0
