/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2019
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.services.cm.admin.utility

import javax.inject.Inject

import com.ericsson.cds.cdi.support.rule.ImplementationInstance
import com.ericsson.cds.cdi.support.spock.CdiSpecification
import com.ericsson.oss.services.cm.admin.domain.SnmpData

import spock.lang.Unroll

/**
 * Unit tests for {@link SnmpDataHelper}
 */
class SnmpdataHelperSpec extends CdiSpecification {

    @Inject
    private SnmpDataHelper snmpDataHelper;

    @ImplementationInstance
    private PasswordHelper passwordHelper = Mock(PasswordHelper);

    @Unroll
    def "Verify Decode and from with valid snmpString string"() {
        given: "snmpString input"
        def  snmpString = "{" + "AUTH_NO_PRIV,AES128,password,SHA1,password,user" + "}"
        when: 'snmpString is decoded to SnmpData'
        final SnmpData outputSnmpData = snmpDataHelper.from(snmpString)
        then:
        outputSnmpData.snmpSecurityLevel == "AUTH_NO_PRIV"
        outputSnmpData.snmpAuthenticationProtocol == "AES128"
        outputSnmpData.snmpAuthenticationPassword == "password"
        outputSnmpData.snmpPrivacyProtocol == "SHA1"
        outputSnmpData.snmpPrivacyPassword == "password"
        outputSnmpData.user == "user"
    }

    @Unroll
    def "Verify Decode and from with valid snmpString string with blank"() {
        given: "snmpString input"
        def  snmpString = "{" + "AUTH_NO_PRIV,AES128,password,SHA1,  password,user" + "}"
        when: 'snmpString is decoded to SnmpData'
        final SnmpData outputSnmpData = snmpDataHelper.from(snmpString)
        then:
        outputSnmpData.snmpSecurityLevel == "AUTH_NO_PRIV"
        outputSnmpData.snmpAuthenticationProtocol == "AES128"
        outputSnmpData.snmpAuthenticationPassword == "password"
        outputSnmpData.snmpPrivacyProtocol == "SHA1"
        outputSnmpData.snmpPrivacyPassword == "password"
        outputSnmpData.user == "user"
    }

    @Unroll
    def "Verify from with valid snmpArray"() {
        given: "snmpData input"
        def   snmpDataArray = [
            "securityLevel:NO_AUTH_NO_PRIV",
            "authProtocol:NONE",
            "authPassword:encryptedPassword",
            "privProtocol:NONE",
            "privPassword:encryptedPassword",
            "user:defaultuser"
        ] as String[]

        when:
        final SnmpData outputSnmpData = snmpDataHelper.from(snmpDataArray)

        then:
        outputSnmpData.snmpSecurityLevel == "NO_AUTH_NO_PRIV"
        outputSnmpData.snmpAuthenticationProtocol == "NONE"
        outputSnmpData.snmpAuthenticationPassword == "encryptedPassword"
        outputSnmpData.snmpPrivacyProtocol == "NONE"
        outputSnmpData.snmpPrivacyPassword == "encryptedPassword"
        outputSnmpData.user == "defaultuser"
    }

    @Unroll
    def "Verify toParameterValue with valid snmpData"() {
        given: "snmpData input"

        def  snmpDataArray = [
            'securityLevel:NO_AUTH_NO_PRIV',
            'authProtocol:NONE',
            'authPassword:noencryptedPassword',
            'privProtocol:NONE',
            'privPassword:noencryptedPassword',
            'user:defaultsnmpuser'] as String[]

        def SnmpData snmpData = new SnmpData(snmpDataArray)
        passwordHelper.encryptEncode(_) >> "encryptedPassword"

        when:
        def displayValue = snmpDataHelper.toParmValueString(snmpData)

        then:

        displayValue == "securityLevel:NO_AUTH_NO_PRIV,authPassword:encryptedPassword,authProtocol:NONE,privPassword:encryptedPassword,privProtocol:NONE,user:defaultsnmpuser"
    }
}
