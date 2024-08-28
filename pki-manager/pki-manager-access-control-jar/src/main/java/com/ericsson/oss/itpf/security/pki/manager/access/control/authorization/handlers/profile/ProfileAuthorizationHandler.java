/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.profile;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.EPredefinedRole;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.annotation.Authorize;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;

/**
 * This class is used to authorize profile operations including {@link CertificateProfile}, {@link EntityProfile}, {@link TrustProfile}
 * 
 * @author tcsvmeg
 * 
 */
public class ProfileAuthorizationHandler {

    @Inject
    public Logger logger;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * Method used to authorize import of profiles
     */
    @Authorize(action = "create", resource = "profile_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeImportProfiles() {
        logger.debug("User authorized to perform import of profiles");
    }

    /**
     * Method used to authorize export of profiles
     */
    @Authorize(action = "read", resource = "read_profiles", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeExportProfiles() {
        logger.debug("User authorized to perform export of profiles");
    }

    /**
     * Method used to authorize listing/get of profiles
     */
    @Authorize(action = "read", resource = "read_profiles", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeGetProfile() {
        logger.info("User authorized to perform listing of profiles");
    }

    /**
     * Method used to authorize creation of profiles
     */
    @Authorize(action = "create", resource = "profile_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeCreateProfile() {
        logger.debug("User authorized to perform creation of profiles");
    }

    /**
     * Method used to authorize updation of profiles
     */
    @Authorize(action = "update", resource = "profile_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeUpdateProfile() {
        logger.debug("User authorized to perform updation of profiles");

    }

    /**
     * Method used to authorize deletion of profiles
     */
    @Authorize(action = "delete", resource = "profile_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeDeleteProfile() {
        logger.debug("User authorized to perform deletion of profiles");
    }

}
