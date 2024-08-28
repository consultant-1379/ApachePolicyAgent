#!/bin/bash

### acceptance_tests.sh - sandbox acceptance test using shunit2 ###

function testPostInstallBasicExecutionSuccess()
{
	echo "exit 0" > ${SHUNIT_TMPDIR}/bin/sso_policy_agent_install.sh
	bash ../../main/scripts/postinstall.sh
	assertEquals 0 ${?}
}

function testPostInstallBasicExecutionFailure()
{
	mkdir -p ${SHUNIT_TMPDIR}/bin && echo "exit 1" > ${SHUNIT_TMPDIR}/bin/sso_policy_agent_install.sh
	bash ../../main/scripts/postinstall.sh
	assertNotEquals 0 ${?}
}

function testPostInstallUpgradeWorkaround()
{
	mkdir -p ${SHUNIT_TMPDIR}/bin && echo "exit 0" > ${SHUNIT_TMPDIR}/bin/sso_policy_agent_install.sh
	mkdir -p ${SHUNIT_TMPDIR}/web_agents/apache22_agent/installer-logs/audit/
	mkdir -p ${SHUNIT_TMPDIR}/web_agents/apache22_agent/Agent_001
	assertTrue "Mock Agent_001 directory not created" "[ -d ${SHUNIT_TMPDIR}/web_agents/apache22_agent/Agent_001 ]"
	echo "3.0-04" > ${SHUNIT_TMPDIR}/web_agents/apache22_agent/installer-logs/audit/install.log
	bash ../../main/scripts/postinstall.sh
	assertTrue "Mock Agent_001 directory not removed during upgrade" "[ ! -d ${SHUNIT_TMPDIR}/web_agents/apache22_agent/Agent_001 ]"
}

function testBinFilesAreExecutable()
{
	mkdir -p ${SHUNIT_TMPDIR}/bin && echo "exit 0" > ${SHUNIT_TMPDIR}/bin/sso_policy_agent_install.sh
	bash ../../main/scripts/postinstall.sh

	for file in ${SHUNIT_TMPDIR}/web_agents/apache22_agent/bin/*; do
		[ -x ${file} ]
		assertEquals 0 ${?}
	done
}

function testCertFilePermissions()
{
	mkdir -p ${SHUNIT_TMPDIR}/bin && echo "exit 0" > ${SHUNIT_TMPDIR}/bin/sso_policy_agent_install.sh
	bash ../../main/scripts/postinstall.sh

	for file in ${SHUNIT_TMPDIR}/ssoserverapache.*; do
		assertEquals 600 $( stat -c %a ${file} )
	done
}

function testPreRemoveWithSSLConfigFile()
{
	touch ${SHUNIT_TMPDIR}/ssl.conf.OFF
	bash ../../main/scripts/preremove.sh
	[ -f ${SHUNIT_TMPDIR}/ssl.conf.OFF ]
	assertNotEquals "SSL config file not renamed" 0 ${?}
	[ -f ${SHUNIT_TMPDIR}/ssl.conf ]
	assertEquals "SSL config file not renamed correctly" 0 ${?}
}

function testPolicyAgentInstallSuccess()
{
	# echo "passw0rd" > /cygdrive/c/Temp/agent-access-other.txt
	setupMockPolicyAgentEnv
	assertTrue "[ -f ${SHUNIT_TMPDIR}/bin/sso_policy_agent_install.sh ]"
	assertTrue "[ -f ${SHUNIT_TMPDIR}/httpd/conf/httpd.conf ]"
	assertTrue "[ -d ${SHUNIT_TMPDIR}/httpd/conf.d ]"
	bash -x ../../main/scripts/postinstall.sh test-mode ${SHUNIT_TMPDIR}/etc/global.properties ${SHUNIT_TMPDIR}/etc/env-vars.conf
	ret_val=${?}
	if ! cygcheck -V > /dev/null 2>&1; then
		assertEquals "Policy Agent install script failed" 0 ${ret_val}
	fi
}

### Suite functions ###
function oneTimeSetUp()
{
	. "../resources/lib/test_env.sh"
	setupTmpDir
	export RPM_INSTALL_PREFIX=${SHUNIT_TMPDIR}
	createFakeCertFiles ${RPM_INSTALL_PREFIX}
	
	# BASH only :(
	for func in "logger jar amf-state-mock semanage-mock restorecon-mock getsebool-mock setsebool-mock"
	do
		export -f ${func}
	done
}

function setUp()
{
	backupPostInstallScript
}

function tearDown()
{
	[ -d ${SHUNIT_TMPDIR}/web_agents ] && rm -rf ${SHUNIT_TMPDIR}/web_agents
	restorePostInstallScript
}

### Helper functions ###
function setupTmpDir()
{
	cd ../../../target/shunit
	SHUNIT_TMPDIR=$( pwd )
	cd - > /dev/null 2>&1
}

function setupMockPolicyAgentEnv()
{
	mkdir -p ${SHUNIT_TMPDIR}/httpd/{conf.d,conf}
	echo "ServerName some.fake.server" > ${SHUNIT_TMPDIR}/httpd/conf/httpd.conf
}

function backupPostInstallScript()
{
	cp ${SHUNIT_TMPDIR}/bin/sso_policy_agent_install.sh ${SHUNIT_TMPDIR}/bin/sso_policy_agent_install.sh.bak
}

function restorePostInstallScript()
{
	mv ${SHUNIT_TMPDIR}/bin/sso_policy_agent_install.sh.bak ${SHUNIT_TMPDIR}/bin/sso_policy_agent_install.sh
}

## Run the tests
## (we are currently in src/test/bash)
. "../resources/lib/shunit2-2.1.6/src/shunit2"
