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
 -----------------------------------------------------------------------------*/

package com.ericsson.oss.services.cm.admin.security

import static com.ericsson.oss.services.cm.admin.security.AccessControl.APP_PARAM_UPDATE
import static com.ericsson.oss.services.cm.admin.security.AccessControl.APP_PARAM_VIEW

import com.ericsson.oss.itpf.sdk.security.accesscontrol.EAccessControl
import com.ericsson.oss.services.cm.error.exception.UnauthorizedServiceAccessException


import spock.lang.Specification

class AdminAuthorizerSpec extends Specification {

    def "When eAccessControl isAuthorized returns true then authorizer shouldn't throw exception"() {
        given:
        EAccessControl eAccessControl = Mock()
        eAccessControl.isAuthorized(*_) >> true
        def authorizer = new AdminAuthorizer(eAccessControl)

        when:
        authorizer.authorize(accessControl)

        then:
        noExceptionThrown()

        where:
        accessControl << AccessControl.values()
    }

    def "When eAccessControl isAuthorized returns false then authorizer should throw Exception"() {
        given:

        EAccessControl eAccessControl = Mock()
        eAccessControl.isAuthorized(*_) >> false
        def authorizer = new AdminAuthorizer(eAccessControl)

        when:
        authorizer.authorize(accessControl)

        then:
        thrown(exception)

        where:
        accessControl   | exception
        APP_PARAM_UPDATE    | UnauthorizedServiceAccessException
        APP_PARAM_VIEW      | UnauthorizedServiceAccessException

    }
}
