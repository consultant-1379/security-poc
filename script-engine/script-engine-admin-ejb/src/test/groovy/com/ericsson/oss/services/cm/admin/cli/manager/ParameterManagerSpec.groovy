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
package com.ericsson.oss.services.cm.admin.cli.manager


import javax.inject.Inject

import com.ericsson.cds.cdi.support.spock.CdiSpecification
import com.ericsson.oss.services.cm.admin.domain.SnmpData

class ParameterManagerSpec extends CdiSpecification {

    @Inject
    ParameterManager parameterManager


    def 'verify the parm is supported or not'() {
        given: 'command input'

        when: 'execute command'
        Boolean result = parameterManager.isSupportedParm(parmName)

        then: 'response returned'
        result == returnresult

        where:
        parmName                    | returnresult
        "t"                         | false
        "NODE_SNMP_SECURITY"        | true
        "NODE_SNMP_INIT_SECURITY"   | true
        "AP_SNMP_AUDIT_TIME"        | true
    }

    def 'return the storage type class from parm name'() {
        given: 'parm name'

        when: 'get the parm class'
        Class type = parameterManager.getStorageType(parmName)

        then: 'parmclass returned'
        type == tpyeclass

        where:
        parmName                    | tpyeclass
        "NODE_SNMP_SECURITY"        | String[].class
        "NODE_SNMP_INIT_SECURITY"   | String[].class
        "AP_SNMP_AUDIT_TIME"        | String.class
    }

    def 'return the data type class from parm name'() {
        given: 'parm name'

        when: 'get the data type'
        Class datatype = parameterManager.getDataType(parmName)

        then: 'typeclass returned'
        datatype == dataclass

        where:
        parmName                    | dataclass
        "NODE_SNMP_SECURITY"        | SnmpData.class
        "NODE_SNMP_INIT_SECURITY"   | SnmpData.class
        "AP_SNMP_AUDIT_TIME"        | String.class
    }
}