/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2020
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.services.cm.admin.domain

import com.ericsson.oss.services.cm.admin.validation.ValidationResult

import spock.lang.Specification

class SnmpDataSpec extends Specification {

    def 'SnmpData with valid String array,  validation pass '() {
        given:

        def stringValues = [
            'securityLevel:AUTH_PRIV',
            "authPassword:onlytset",
            "authProtocol:MD5",
            "privPassword:onlytest",
            "privProtocol:AES128",
            "user:newuserprefix"
        ] as String[]
        final SnmpData snmpData = new SnmpData(stringValues);

        when:
        ValidationResult result = snmpData.validate()

        then:
        result.valid == true
    }


    def 'SnmpData with invalid String array value,  validation fail '() {
        given:

        def stringValues = [
            'securityLevel:AUTH_PRIV',
            "authPassword:onlytset",
            "authProtocol:error",
            "privPassword:onlytest",
            "privProtocol:AES128",
            "user:newuserprefix"
        ] as String[]
        final SnmpData snmpData = new SnmpData(stringValues);

        when:
        ValidationResult result = snmpData.validate()

        then:
        result.valid == false
        result.errorMessage == "Field authProtocol must be one of [NONE, MD5, SHA1]."
    }

    def 'SnmpData with valid parm value,  validation pass '() {
        given:

        final SnmpData snmpData = new SnmpData(snmpSecurityLevel, snmpAuthenticationProtocol, snmpAuthenticationPassword,
                snmpPrivacyProtocol, snmpPrivacyPassword, user);

        when:
        ValidationResult result = snmpData.validate()

        then:
        result.valid == true

        where:
        snmpSecurityLevel | snmpAuthenticationProtocol |snmpAuthenticationPassword | snmpPrivacyProtocol | snmpPrivacyPassword | user
        "AUTH_PRIV"       | "MD5"                      | "onlytset"                | "AES128"            | "onlytest"          | "newuserprefix"
        "NO_AUTH_NO_PRIV" | "NONE"                     | "onlytset"                | "NONE"              | "onlytest"          | "newuserprefix"
        "NO_AUTH_NO_PRIV" | "MD5"                      | ""                        | "AES128"            | ""                  | "newuserprefix"
        "AUTH_PRIV"       | "MD5"                      | "4ge%43:34444"            | "AES128"            | "ge!%^*()egn"       | "01234567890123456789"
        "AUTH_NO_PRIV"    | "MD5"                      | "onlytset"                | "AES128"            | "onlytest"          | "newuserprefix"
        "AUTH_NO_PRIV"    | "MD5"                      | "onlytset"                | "NONE"              | ""                  | "newuserprefix"
    }

    def 'SnmpData with invalid parm value,  validation fail '() {
        given:

        final SnmpData snmpData = new SnmpData(snmpSecurityLevel, snmpAuthenticationProtocol, snmpAuthenticationPassword,
                snmpPrivacyProtocol, snmpPrivacyPassword, user);

        when:
        ValidationResult result = snmpData.validate()

        then:
        result.valid == false
        result.errorMessage == errorMessage

        where:
        snmpSecurityLevel | snmpAuthenticationProtocol |snmpAuthenticationPassword | snmpPrivacyProtocol | snmpPrivacyPassword | user                   |errorMessage
        "AUTH_PRIV"       | "MD5"                      | "onlytset"                | "AES128"            | "only"              | "01234567890123456789" |"Field privPassword length should not be less than 8."
        "NO_AUTH_NO_PRIV" | "NONE"                     | "onlytset"                | "NONE"              | "onlytest"          | ""                     |"Field user should not be empty."
        "NO_AUTH_NO_PRIV" | "MD5"                      | ""                        | "AES128"            | ""                  | "012345678901234567890"|"Field user length should not be more than 20."
        "AUTH_PRIV"       | "MD5"                      | "4ge%43:34444"            | "ABC"               | "ge!%^*()egn"       | "01234567890123456789" |"Field privProtocol must be one of [NONE, DES, AES128]."
        "AUTH_NO_PRIV"    | "ABC"                      | "onlytset"                | "AES128"            | "onlytest"          | "newuserprefix"        |"Field authProtocol must be one of [NONE, MD5, SHA1]."
        "AUTH_NO_PRIV"    | "MD5"                      | "only"                    | "NONE"              | ""                  | "newuserprefix"        |"Field authPassword length should not be less than 8."
    }
}
