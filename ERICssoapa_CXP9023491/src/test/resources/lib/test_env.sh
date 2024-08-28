### Environment setup for acceptance_tests.sh ###


###
### Variables
###

###
### FUNCTIONS
###
function logger()
{
	shift 5
	echo $@
}

function createFakeCertFiles()
{
	#mkdir -p ${1}/{current-cert,new-cert,current-key}
	echo "Some content" > ${1}/ssoserverapache.key
	echo "Some other content" > ${1}/ssoserverapache.crt
}

function removeFakeCertFiles()
{
	rm -rf ${1}/{current-cert,new-cert,current-key}
}

### Mock functions to emulate commands ###
function jar()
{
	if ! type -p "unzip" > /dev/null 2>&1; then
		${JAVA_HOME}/bin/jar ${@}
	else
		shift
		unzip ${@}
	fi
}

function amf-state-mock()
{
	echo "safSu=httpd_App-SuType-0,safSg=httpd,safApp=httpd_App
        saAmfSUAdminState=UNLOCKED(1)
        saAmfSUOperState=ENABLED(1)
        saAmfSUPresenceState=UNINSTANTIATED(1)
        saAmfSUReadinessState=IN-SERVICE(2)
safSu=httpd_App-SuType-1,safSg=httpd,safApp=httpd_App
        saAmfSUAdminState=UNLOCKED(1)
        saAmfSUOperState=ENABLED(1)
        saAmfSUPresenceState=UNINSTANTIATED(1)
        saAmfSUReadinessState=IN-SERVICE(2)"
}

function semanage-mock()
{
	echo "Invoking semanage-mock"
}

function restorecon-mock()
{
	echo "Invoking restorecon-mock"
}

function getsebool-mock()
{
	echo "Invoking getsebool-mock"
	echo "off"
}

function setsebool-mock()
{
	echo "Invoking setsebool-mock"
}
