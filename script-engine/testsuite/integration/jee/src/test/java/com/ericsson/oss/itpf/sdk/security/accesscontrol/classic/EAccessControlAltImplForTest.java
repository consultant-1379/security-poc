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
package com.ericsson.oss.itpf.sdk.security.accesscontrol.classic;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Arrays;
import java.util.HashSet;
import java.util.Map;
import java.util.Set;

import org.apache.commons.lang.StringUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.security.accesscontrol.EAccessControl;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.EPredefinedRole;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.ESecurityAction;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.ESecurityResource;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.ESecuritySubject;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.ESecurityTarget;

/* Implementation of EAccessControl interface for testing.
 */
public class EAccessControlAltImplForTest implements EAccessControl {

    private static final Logger LOGGER = LoggerFactory.getLogger(EAccessControlAltImplForTest.class);

    /**
     * The expected authorized calls to isAuthorized.
     * The string format is based on the arguments passed to isAuthorized: subject;annotatedRoles;resource;action
     * see the accesscontrol annotations for more details
     */
    private static final String[] AUTHORIZED = new String[] {
            "authorized_user;config_app_param;read",
            "authorized_user;config_app_param;update"
    };

    /**
     * Same as AUTHORIZED but for unauthorized requests.
     */
    private static final String[] UNAUTHORIZED = new String[] {
            "unauthorized_user;config_app_param;read",
            "unauthorized_user;config_app_param;update"
    };

    @Override
    public ESecuritySubject getAuthUserSubject()  {

        LOGGER.info("called getAuthUserSubject() in AccessControlAltImplForTest");

        String tmpDir;
        final String osName = System.getProperty("os.name");
        if (osName.equals("Linux")) {
            tmpDir = "/tmp";
        } else {
            tmpDir = System.getProperty("java.io.tmpdir");
        }

        // get userid from currentAuthUser file in tmpDir
        final String useridFile = String.format("%s/currentAuthUser", tmpDir);
        String toruser;
        try {
            toruser = new String(Files.readAllBytes(Paths.get(useridFile)));
        } catch (final IOException ioe) {
            LOGGER.error("Error reading {}",useridFile);
            toruser = "error";
        }

        LOGGER.info("getAuthUserSubject: toruser is <{}>",toruser);
        return new ESecuritySubject(toruser);
    }

    @Override
    public boolean isAuthorized(final ESecurityResource secResource, final ESecurityAction secAction) {
        throw new UnsupportedOperationException("This is the script-engine dummy implementation of EAccessControl, this method is not implemented!");
    }

    @Override
    @SuppressWarnings("squid:CallToDeprecatedMethod")
    public boolean isAuthorized(final ESecurityResource secResource, final ESecurityAction secAction, final EPredefinedRole[] roles) {
        throw new UnsupportedOperationException("This is the script-engine dummy implementation of EAccessControl, this method is not implemented!");
    }

    @Override
    public boolean isAuthorized(final ESecuritySubject secSubject, final ESecurityResource secResource, final ESecurityAction secAction) {

        final String action = secAction.getActionId().toLowerCase();
        final String subject = secSubject.getSubjectId().toLowerCase();
        final String resource = secResource.getResourceId().toLowerCase();
        final String authorization = String.format("%s;%s;%s", subject, resource, action);

        if (Arrays.asList(AUTHORIZED).contains(authorization)) {
            LOGGER.info("Authorized: user: {}, resource: {}, action: {}", subject, resource, action);
            return true;
        }

        if (Arrays.asList(UNAUTHORIZED).contains(authorization)) {
            LOGGER.info("Not Authorized: user: {}, resource: {}, action: {}", subject, resource, action);
            return false;
        }

        throw new IllegalStateException("The script-engine dummy access control doesn't expect the authorization string : \"" + authorization
                + "\". Add the authorization string to " + EAccessControlAltImplForTest.class + ".UNAUTHORIZED or .AUTHORIZED");
    }

    /**
     * Un/authorize requests based on the expected calls defined in AUTHORIZED and UNAUTHORIZED arrays.
     * If the request is not expected throws IllegalStateException with the authorization string to be added to one of the arrays.
     */
    @Override
    @SuppressWarnings("squid:CallToDeprecatedMethod")
    public boolean isAuthorized(final ESecuritySubject secSubject, final ESecurityResource secResource, final ESecurityAction secAction,
                                final EPredefinedRole[] roles) {

        throw new UnsupportedOperationException("This is the script-engine dummy implementation of EAccessControl, this method is not implemented!");
    }

    @Override
    public void setAuthUserSubject(final String userName) {
        LOGGER.info("setAuthUserSubject: userName {}",userName);
        if (StringUtils.isEmpty(userName)) {
            throw new IllegalArgumentException("Illegal argument detected, userName must not be null.");
        }
    }

    @Override
    public boolean isUserInRole(final String role) {
        return true;
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * com.ericsson.oss.itpf.sdk.security.accesscontrol.EAccessControl#isAuthorized(com.ericsson.oss.itpf.sdk.security.accesscontrol.ESecuritySubject,
     * com.ericsson.oss.itpf.sdk.security.accesscontrol.ESecurityResource, com.ericsson.oss.itpf.sdk.security.accesscontrol.ESecurityAction,
     * java.util.Set)
     */
    @Override
    public boolean isAuthorized(final ESecuritySubject secSubject, final ESecurityResource secResource, final ESecurityAction secAction,
                                final Set<ESecurityTarget> targets) {
        // TODO Auto-generated method stub
        return false;
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * com.ericsson.oss.itpf.sdk.security.accesscontrol.EAccessControl#isAuthorized(com.ericsson.oss.itpf.sdk.security.accesscontrol.ESecurityResource
     * , com.ericsson.oss.itpf.sdk.security.accesscontrol.ESecurityAction, java.util.Set)
     */
    @Override
    public boolean isAuthorized(final ESecurityResource secResource, final ESecurityAction secAction, final Set<ESecurityTarget> targets) {
        // TODO Auto-generated method stub
        return false;
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * com.ericsson.oss.itpf.sdk.security.accesscontrol.EAccessControl#isAuthorized(com.ericsson.oss.itpf.sdk.security.accesscontrol.ESecuritySubject,
     * java.util.Set)
     */
    @Override
    public boolean isAuthorized(final ESecuritySubject secSubject, final Set<ESecurityTarget> targets) {
        // TODO Auto-generated method stub
        return false;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.sdk.security.accesscontrol.EAccessControl#isAuthorized(java.util.Set)
     */
    @Override
    public boolean isAuthorized(final Set<ESecurityTarget> targets) {
        // TODO Auto-generated method stub
        return false;
    }

    /*
     * (non-Javadoc)
     *
     * @see
     * com.ericsson.oss.itpf.sdk.security.accesscontrol.EAccessControl#isAuthorized(com.ericsson.oss.itpf.sdk.security.accesscontrol.ESecuritySubject,
     * com.ericsson.oss.itpf.sdk.security.accesscontrol.ESecurityTarget)
     */
    @Override
    public boolean isAuthorized(final ESecuritySubject secSubject, final ESecurityTarget target) {
        // TODO Auto-generated method stub
        return false;
    }

    @Override
    public boolean isAuthorized(final ESecurityTarget target) {
        return false;
    }

    @Override
    public boolean checkUserExists(final ESecuritySubject var1) {
        return true;
    }

    @Override
    public Set<ESecurityTarget> getTargetsForSubject() {
        return new HashSet<>();
    }

    @Override
    public Set<ESecurityTarget> getTargetsForSubject(final ESecuritySubject var1) {
        return new HashSet<>();
    }

    @Override
    public Map<ESecurityResource, Set<ESecurityAction>> getActionsForResources(final ESecuritySubject secSubject,
                                                                               final Set<ESecurityResource> secResources) {
        // TODO Auto-generated method stub
        return null;
    }

    @Override
    public Map<ESecurityResource, Set<ESecurityAction>> getActionsForResources(final Set<ESecurityResource> secResources) {
        // TODO Auto-generated method stub
        return null;
    }
}
