#
# RPM post install script location
#

LOGGER_TAG="TOR_SSO_PA"
APACHE_CERT_DIR=/ericsson/tor/data/certificates/sso
APACHE_CERT_PREFIX=ssoserverapache
PKI_CERT_DIR=/etc/pki/tls/certs/
PKI_KEY_DIR=/etc/pki/tls/private/
GREP=/bin/grep

##
## INFORMATION print
##
info()
{
	if [ ${#} -eq 0 ]; then
		while read data; do
			logger -s -t ${LOGGER_TAG} -p user.notice "INFORMATION ( ERICssoapa %postinstall ): ${data}"
		done
	else
		logger -s -t ${LOGGER_TAG} -p user.notice "INFORMATION ( ERICssoapa %postinstall ): $@"
	fi
}

##
## ERROR print
##
error()
{
	if [ ${#} -eq 0 ]; then
		while read data; do
			logger -s -t ${LOGGER_TAG} -p user.err "ERROR ( ERICssoapa %postinstall ): ${data}"
		done
	else
		logger -s -t ${LOGGER_TAG} -p user.err "ERROR ( ERICssoapa %postinstall ): $@"
	fi
}

##
## WARN print
##
warn()
{
	if [ ${#} -eq 0 ]; then
		while read data; do
			logger -s -t ${LOGGER_TAG} -p user.warning "WARN ( ERICssoapa %postinstall ): ${data}"
		done
	else
		logger -s -t ${LOGGER_TAG} -p user.warning "WARN ( ERICssoapa %postinstall ): $@"
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


info "Sourcing environment variables from ${RPM_INSTALL_PREFIX}/etc/env-vars.conf"
. ${RPM_INSTALL_PREFIX}/etc/env-vars.conf

[ -z "$SSO_HOME" ] && error "Could not source ${RPM_INSTALL_PREFIX}/etc/env-vars.conf" || info "Sourced ${RPM_INSTALL_PREFIX}/etc/env-vars.conf successfully"

# Fix for upgrading to Policy Agent 3.3.0 - 
#
#   if version 3.0.4 is already installed but we
#   want to upgrade to 3.3.0, we must first uninstall
#   the existing agent by removing the existing 'Agent_001'
#   folder
if ${GREP} -q "3.0-04" ${SSO_HOME}/web_agents/apache22_agent/installer-logs/audit/install.log > /dev/null 2>&1; then
	if [ -f ${SSO_HOME}/Apache-v2.2-Linux-64-agent-3.3.0.zip ]; then
		POLICY_AGENT_ARCHIVE="${SSO_HOME}/Apache-v2.2-Linux-64-agent-3.3.0.zip"
		rm -rf ${SSO_HOME}/web_agents/apache22_agent
	fi
fi

# Copy the certificate
[ -f ${PKI_KEY_DIR}/${APACHE_CERT_PREFIX}.key -a -f ${PKI_CERT_DIR}/${APACHE_CERT_PREFIX}.crt ] && \
info "Apache certificate and key file exist, overwriting" || \
info "Copying Apache certificate and key file to ${PKI_KEY_DIR} and ${PKI_CERT_DIR}"
cp -f ${APACHE_CERT_DIR}/${APACHE_CERT_PREFIX}.key ${PKI_KEY_DIR}
cp -f ${APACHE_CERT_DIR}/${APACHE_CERT_PREFIX}.crt ${PKI_CERT_DIR}
chmod 600 ${PKI_KEY_DIR}/${APACHE_CERT_PREFIX}.key
chmod 600 ${PKI_CERT_DIR}/${APACHE_CERT_PREFIX}.crt

# Go to $SSO_HOME
cd $SSO_HOME

# unpack the policy agent
info "Unpacking $POLICY_AGENT_ARCHIVE"
jar -xvf $POLICY_AGENT_ARCHIVE > /dev/null 2>&1
[ -d $SSO_HOME/web_agents/apache22_agent ] && info "Policy Agent archive unpacked" || error "Policy Agent not unpacked"

# Setup the policy agent install executables
chmod +x $SSO_HOME/web_agents/apache22_agent/bin/*

# To be run ONLY if we're on cygwin (testing locally)
if cygcheck -V > /dev/null 2>&1; then
	cp -f /cygdrive/c/Temp/Apache-v2.2-WINNT-32-Agent-3.3.0/web_agents/apache22_agent/bin/{*.exe,*.dll,*.chk,*.pdb} \
	$SSO_HOME/web_agents/apache22_agent/bin
	rm -f $SSO_HOME/web_agents/apache22_agent/bin/certutil
fi

if [ "${1}" = "test-mode" ]; then
	info "Executing $SSO_HOME/bin/sso_policy_agent_install.sh in test mode"
	bash -x $SSO_HOME/bin/sso_policy_agent_install.sh ${2} ${3}
else
	info "Executing $SSO_HOME/bin/sso_policy_agent_install.sh"
	bash $SSO_HOME/bin/sso_policy_agent_install.sh
fi

ret_val=${?}

info "Exit code from $SSO_HOME/bin/sso_policy_agent_install.sh was ${ret_val}"

[ "${ret_val}" -ne 0 ] && graceful_exit 1 "sso_policy_agent_install.sh failed, exiting"

exit 0
