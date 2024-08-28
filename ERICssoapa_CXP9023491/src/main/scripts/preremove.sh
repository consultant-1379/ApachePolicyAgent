#
# RPM pre remove scriptlet
#

MV=/bin/mv
APACHE_CERT_DIR=/ericsson/tor/data/certificates/sso
APACHE_CERT_PREFIX=ssoserverapache
PKI_CERT_DIR=/etc/pki/tls/certs/
PKI_KEY_DIR=/etc/pki/tls/private/

##
## INFORMATION print
##
info()
{
	if [ ${#} -eq 0 ]; then
		while read data; do
			logger -s -t TOR_SSO_PA -p user.notice "INFORMATION ( ERICssoapa %preun ): ${data}"
		done
	else
		logger -s -t TOR_SSO_PA -p user.notice "INFORMATION ( ERICssoapa %preun ): $@"
	fi
}

## ERROR print
##
error()
{
	if [ ${#} -eq 0 ]; then
		while read data; do
			logger -s -t TOR_SSO_PA -p user.err "ERROR ( ERICssoapa %preun ): ${data}"
		done
	else
		logger -s -t TOR_SSO_PA -p user.err "ERROR ( ERICssoapa %preun ): $@"
	fi
}

info "Sourcing environment variables from ${RPM_INSTALL_PREFIX}/etc/env-vars.conf"
. ${RPM_INSTALL_PREFIX}/etc/env-vars.conf

[ -z "$SSO_HOME" ] && error "Could not source ${RPM_INSTALL_PREFIX}/etc/env-vars.conf" || info "Sourced ${RPM_INSTALL_PREFIX}/etc/env-vars.conf successfully"

# Rename ${DEFAULT_SSL_CONF}.OFF back to ${DEFAULT_SSL_CONF}
if [ -f $HTTPD_CONF_D_HOME/${DEFAULT_SSL_CONF}.OFF ]; then
	info "Disabling default SSL configuration"
	${MV} $HTTPD_CONF_D_HOME/${DEFAULT_SSL_CONF}.OFF $HTTPD_CONF_D_HOME/${DEFAULT_SSL_CONF}
fi

# if [ $1 -eq 0 ]; then
# 	info "Final erase of package being performed, cleaning up"

# 	info "Creating temporary response file for uninstallation"
# 	echo "CONFIG_DIR= /etc/httpd/conf" > /tmp/pa_uninstall.tmp

# 	# Run the Policy Agent uninstaller
# 	if [ -x $SSO_HOME/web_agents/apache22_agent/bin/agentadmin ]; then
# 		$SSO_HOME/web_agents/apache22_agent/bin/agentadmin --uninstall --useResponse /tmp/pa_uninstall.tmp 2>&1 | info
# 	fi

# 	# Remove temporary response file
# 	rm -f /tmp/pa_uninstall.tmp

# 	# Delete any backups made during installation
# 	${RM} -f $HTTPD_CONF_HOME/httpd.conf-preAmAgent-*

# 	# Remove certificates
# 	if [ -f ${PKI_KEY_DIR}/${APACHE_CERT_PREFIX}.key -a -f ${PKI_CERT_DIR}/${APACHE_CERT_PREFIX}.crt ]; then
# 		info "Removing web server certificate and private key"
# 		rm -f ${PKI_KEY_DIR}/${APACHE_CERT_PREFIX}.key ${PKI_CERT_DIR}/${APACHE_CERT_PREFIX}.crt
# 	fi
	
# 	# Remove existing additions from ${SYSCONFIG_FILE}
# 	for pattern in "LD_LIBRARY_PATH_64" "NSS_STRICT_NOFORK" "NSS_STRICT_SHUTDOWN"; do
# 		${GREP} -q ${pattern} ${SYSCONFIG_FILE} > /dev/null 2>&1
# 		if [ ${?} -eq 0 ]; then
# 			${SED} -i "/${pattern}/d" ${SYSCONFIG_FILE}
# 		fi
# 	done

# 	# Remove SSO-specific httpd config file
# 	if [ -f $HTTPD_CONF_D_HOME/$SSO_APACHE_CONF ]; then
# 		info "Removing SSO Apache config file $HTTPD_CONF_D_HOME/$SSO_APACHE_CONF"
# 		rm -f $HTTPD_CONF_D_HOME/$SSO_APACHE_CONF
# 	fi

# 	# Check if the hidden file .amAgentLocator exists and delete it
# 	if [ -f /etc/httpd/.amAgentLocator ]; then
# 		info "Removing Policy Agent 'Agent Locator' file"
# 		rm -f /etc/httpd/.amAgentLocator
# 	fi

# 	# Final cleanup
# 	if [ -d $SSO_HOME/web_agents ]; then
# 		info "Removing Policy Agent folder"
# 		rm -rf $SSO_HOME/web_agents
# 	fi
# fi

info "Cleanup complete"

exit 0