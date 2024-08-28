package com.ericsson.oss.services.cm.admin.cli.validation

import com.ericsson.cds.cdi.support.rule.ImplementationInstance
import com.ericsson.cds.cdi.support.spock.CdiSpecification
import com.ericsson.oss.services.cm.admin.cli.manager.ParameterManager
import com.ericsson.oss.services.cm.admin.utility.PasswordHelper
import com.ericsson.oss.services.cm.admin.validation.ParametersValidationFactory
import com.ericsson.oss.services.cm.admin.validation.ValidationResult

import javax.inject.Inject

class ParameterValidationFactorySpec extends CdiSpecification {
    @Inject
    ParametersValidationFactory parametersValidationFactory

    @Inject
    ParameterManager parameterManager

    @ImplementationInstance
    private PasswordHelper passwordHelper = Mock();

    def 'Verify valid non-SNMP values are validated correctly'() {
        when:
        ValidationResult validationResult = parametersValidationFactory.validateData(paramValue)

        then:
        result == validationResult.isValid()

        where:
        paramValue                | result
        "trf"                     | true
        "123"                     | true
        "[a,b,c]"                 | true
        "{key:value,key2:value2}" | true
    }

    def 'Verify invalid non-SNMP values are invalidated'() {
        when:
        ValidationResult validationResult = parametersValidationFactory.validateData(paramValue)

        then:
        result == validationResult.isValid()

        where:
        paramValue      | result
        '["abc"]'       | false
        '["abc,def"]'   | false
        '["abc","def"]' | false
        '{}'            | false
        '{abc}'         | false
        '{abc:}'        | false
        'abc,def'       | false
        '"abc'          | false
        'abc"'          | false
        '{abc'          | false
        'abc}'          | false
        'abc,'          | false
    }

    def 'Verify valid SNMP values are validated correctly'() {
        given:
        passwordHelper.encryptEncode(_) >> "encryptedPassword"

        when:
        ValidationResult validationResult = parameterManager.paramValidation(paramName, paramValue)

        then:
        result == validationResult.isValid()

        where:
        paramName                 | paramValue                                                                                                                               | result
        "NODE_SNMP_INIT_SECURITY" | "{securityLevel:auth_priv,authProtocol:MD5,authPassword:password,privProtocol:DES,privPassword:password,user:user}"                      | true
        "NODE_SNMP_SECURITY"      | "{securityLevel:NO_AUTH_NO_PRIV,authProtocol:NONE,authPassword:Password123,privProtocol:NONE,privPassword:Password456,user:defaultuser}" | true
        "NODE_SNMP_INIT_SECURITY" | "{securityLevel:auth_no_priv,authProtocol:sha1,authPassword:password,privProtocol:des,privPassword:pass?word,user:user}"                 | true
        "NODE_SNMP_SECURITY"      | "{securityLevel:AUTH_PRIV,authProtocol:MD5,authPassword:test12345,privProtocol:DES,privPassword:TEST12345,user:user}"                    | true
        "NODE_SNMP_INIT_SECURITY" | "{securityLevel:auth_priv,authProtocol:MD5,authPassword:pass@12345,privProtocol:DES,privPassword:xword@12345,user:user}"                 | true
        "AP_SNMP_AUDIT_TIME"      | "04:30"                                                                                                                                  | true
        "AP_SNMP_AUDIT_TIME"      | "66:78"                                                                                                                                  | true
    }

    def 'Verify invalid SNMP values are invalidated'() {
        given:
        passwordHelper.encryptEncode(_) >> "encryptedPassword"

        when:
        ValidationResult validationResult = parameterManager.paramValidation(paramName, paramValue)

        then:
        result == validationResult.isValid()

        where:
        paramName                 | paramValue                                                                                                               | result
        "NODE_SNMP_INIT_SECURITY" | "{auth_priv,ABC,password,SHA,password,user}"                                                                             | false
        "NODE_SNMP_SECURITY"      | "{auth_priv,123,password,456,password,user}"                                                                             | false
        "NODE_SNMP_INIT_SECURITY" | "{}"                                                                                                                     | false
        "NODE_SNMP_SECURITY"      | "{auth,MD5,password,DES,password,user}"                                                                                  | false
        "AP_SNMP_AUDIT_TIME"      | "abcd"                                                                                                                   | false
    }
}
