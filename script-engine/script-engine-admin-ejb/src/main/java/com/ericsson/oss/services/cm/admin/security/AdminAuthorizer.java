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
package com.ericsson.oss.services.cm.admin.security;

import com.ericsson.oss.itpf.sdk.security.accesscontrol.EAccessControl;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.ESecurityAction;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.ESecurityResource;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.ESecuritySubject;
import com.ericsson.oss.services.cm.error.exception.UnauthorizedServiceAccessException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.inject.Inject;

/**
 *  Class providing functions to check user authorization.
 */
public class AdminAuthorizer {

    private final Logger logger = LoggerFactory.getLogger(this.getClass());

    private EAccessControl eAccessControl;

    @Inject
    public AdminAuthorizer(final EAccessControl eAccessControl) {
        this.eAccessControl = eAccessControl;
    }

    public AdminAuthorizer() {
    }

    public void authorize(final AccessControl accessControl) {
        if (!isAuthorized(accessControl)) {
            throw new UnauthorizedServiceAccessException();
        }
    }

    /**
     * Check if authenticated user has required privileges.
     * @param accessControl object containing required privilege (resource:action)
     *
     * @return <code>true</code> if user has required privileges;
     *          otherwise <code>false</code>
     */
    private boolean isAuthorized(final AccessControl accessControl) {
        final ESecuritySubject authUser = getAuthenticatedUser();
        final ESecurityResource resource = accessControl.getResource();
        final ESecurityAction action = accessControl.getAction();

        logger.debug("Access control: {}", accessControl);
        return this.eAccessControl.isAuthorized(authUser, resource, action);
    }

    private ESecuritySubject getAuthenticatedUser() {
        final ESecuritySubject authUserSubject = eAccessControl.getAuthUserSubject();
        return (authUserSubject != null) ? authUserSubject : new ESecuritySubject("invalid_SubjectId");
    }
}