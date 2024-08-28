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
package com.ericsson.oss.itpf.security.pki.manager.access.control.authorization;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.context.ContextService;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.profile.ProfileAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.utils.ContextUtility;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;

/**
 * This class is used to authorize profile operations including both {@link CertificateProfile}, {@link EntityProfile}, {@link TrustProfile}
 * 
 * @author tcsvmeg
 * 
 */
public class ProfileManagementAuthorizationManager {

    @Inject
    public ContextService ctxService;

    @Inject
    public SystemRecorder systemRecorder;

    @Inject
    ProfileAuthorizationHandler profileAuthorizationHandler;

    @Inject
    ContextUtility contextUtility;

    @Inject
    public Logger logger;

    /**
     * Method use to authorize profile operations.
     * 
     * @param actionType
     *            Action of type {@link ActionType}
     */
    public <T extends AbstractProfile> void authorizeProfileOperations(final ActionType actionType) {
        switch (actionType) {
        case IMPORT:
            authorizeImportProfiles();
            break;
        case EXPORT:
            authorizeExportProfiles();
            break;
        case CREATE:
            authorizeCreateProfile();
            break;
        case UPDATE:
            authorizeUpdateProfile();
            break;
        case READ:
            authorizeGetProfile();
            break;
        case DELETE:
            authorizeDeleteProfile();
            break;
        default:
            logger.error("Invalid Action Type {} " , actionType);
            throw new IllegalArgumentException("Invalid Action Type " + actionType);
        }

    }

    /**
     * Method used to perform user context check for profile name available or not.
     */
    public void authorizeIsProfileNameAvailable() {

        if (!(contextUtility.isCredMOperation() || contextUtility.isNSCSOperation())) {

            logger.error("User unauthorized to check profile name available or not");
            systemRecorder.recordError("IS_PROFILE_NAME_AVAILABLE.FAILED", ErrorSeverity.ERROR, "PROFILE_MANAGEMENT", "END_USER", ErrorMessages.SECURITY_VIOLATION_EXCEPTION);

            throw new SecurityViolationException(ErrorMessages.SECURITY_VIOLATION_EXCEPTION);
        }
    }

    /**
     * Method used to perform user context check for import of profiles.
     */
    private void authorizeImportProfiles() {

        logger.debug("Authorizing import of profiles");

        if (!contextUtility.isCredMOperation()) {
            profileAuthorizationHandler.authorizeImportProfiles();
        }

    }

    /**
     * Method used to perform user context check for export of profiles.
     */
    private void authorizeExportProfiles() {

        logger.debug("Authorizing export of profiles");
        profileAuthorizationHandler.authorizeExportProfiles();

    }

    /**
     * Method used to perform user context check for creation of profiles including {@link CertificateProfile}, {@link EntityProfile}, {@link TrustProfile}.
     */
    private void authorizeCreateProfile() {

        logger.debug("Authorizing profile creation");

        if (!contextUtility.isCredMOperation()) {
            profileAuthorizationHandler.authorizeCreateProfile();
        }

    }

    /**
     * Method used to perform user context check for updation of profiles including {@link CertificateProfile}, {@link EntityProfile}, {@link TrustProfile}.
     */
    private <T extends AbstractProfile> void authorizeUpdateProfile() {
        logger.debug("Authorize update profile");

        if (!contextUtility.isCredMOperation()) {
            profileAuthorizationHandler.authorizeUpdateProfile();
        }

    }

    /**
     * Method used to perform user context check for listing of profiles including {@link CertificateProfile}, {@link EntityProfile}, {@link TrustProfile}.
     */
    private void authorizeGetProfile() {

        logger.info("Authorize get profile");

        if (!(contextUtility.isCredMOperation() || contextUtility.isNSCSOperation())) {
            profileAuthorizationHandler.authorizeGetProfile();

        }
    }

    /**
     * Method used to perform user context check for deletion of profiles including {@link CertificateProfile}, {@link EntityProfile}, {@link TrustProfile}.
     */
    private void authorizeDeleteProfile() {

        logger.debug("Authorize delete profile");
        profileAuthorizationHandler.authorizeDeleteProfile();

    }
}
