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

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.SecurityViolationException;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.profile.CAEntityAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.profile.EntityAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.utils.ContextUtility;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;

/**
 * This class is used to authorize entity operations including both {@link CAEntity}, {@link Entity}
 * 
 * @author tcsvmeg
 * 
 */
public class EntityManagementAuthorizationManager {

    @Inject
    private Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    private EntityAuthorizationHandler entityAuthorizationHandler;

    @Inject
    private CAEntityAuthorizationHandler caEntityAuthorizationHandler;

    @Inject
    ContextUtility contextUtility;

    /**
     * Method is used to authorize entity operations.
     * 
     * @param entityType
     *            entityType {@link EntityType}
     * @param actionType
     *            Action of type {@link ActionType}
     */
    public void authorizeEntityOperations(final EntityType entityType, final ActionType actionType) {

        switch (actionType) {

        case IMPORT:
            authorizeImportEntities(entityType);
            break;
        case CREATE:
            authorizeCreateEntity(entityType);
            break;
        case UPDATE:
            authorizeUpdateEntity(entityType);
            break;
        case READ:
            authorizeGetEntity(entityType);
            break;
        case DELETE:
            authorizeDeleteEntity(entityType);
            break;
        default:
            logger.error("Invalid entity operation {} " , actionType);
            throw new IllegalArgumentException("Invalid entity operation " + actionType);
        }

    }

    /**
     * Method is used to authorize OTP operations.
     * 
     * @param actionType
     *            Action of type {@link ActionType}
     */
    public void authorizeOTPOperations(final ActionType actionType) {

        switch (actionType) {

        case READ:
            authorizeGetOTP();
            break;
        case UPDATE:
            authorizeUpdateOTP();
            break;
        default:
            logger.error("Invalid OTP operation {} " , actionType);
            throw new IllegalArgumentException("Invalid OTP operation " + actionType);

        }

    }

    /**
     * Method is used to authorize get enrollment info.
     */
    public void authorizeGetEnrollmentInfo() {

        if (!contextUtility.isNSCSOperation()) {

            logger.error("User unauthorized to get enrollment info.");
            systemRecorder.recordError("GET_ENROLLMENT_INFO.FAILED", ErrorSeverity.ERROR, "ENTITY_MANAGEMENT", "END_USER", ErrorMessages.SECURITY_VIOLATION_EXCEPTION);

            throw new SecurityViolationException(ErrorMessages.SECURITY_VIOLATION_EXCEPTION);
        }

    }

    /**
     * Method is used to authorize entity name available check.
     */
    public void authorizeIsEntityNameAvailable() {

        if (!(contextUtility.isNSCSOperation() || contextUtility.isCredMOperation())) {

            logger.error("User unauthorized to check entity name available");
            systemRecorder.recordError("GET_OTP.FAILED", ErrorSeverity.ERROR, "ENTITY_MANAGEMENT", "END_USER", ErrorMessages.SECURITY_VIOLATION_EXCEPTION);

            throw new SecurityViolationException(ErrorMessages.SECURITY_VIOLATION_EXCEPTION);
        }

    }

    /**
     * Method is used to authorize get OTP.
     */
    private void authorizeGetOTP() {

        if (!contextUtility.isNSCSOperation()) {

            logger.error("User unauthorized for get OTP");
            systemRecorder.recordError("GET_OTP.FAILED", ErrorSeverity.ERROR, "ENTITY_MANAGEMENT", "END_USER", ErrorMessages.SECURITY_VIOLATION_EXCEPTION);

            throw new SecurityViolationException(ErrorMessages.SECURITY_VIOLATION_EXCEPTION);
        }

    }

    /**
     * Method is used to authorize update OTP.
     */
    private void authorizeUpdateOTP() {

        if (!(contextUtility.isCredMOperation() || contextUtility.isNSCSOperation())) {

            logger.debug("Authorizing update OTP");
            entityAuthorizationHandler.authorizeUpdateEntity();
        }

    }

    /**
     * Method is used to authorize is OTP valid.
     */
    public void authorizeIsOTPValid() {

        if (!contextUtility.isCredMOperation()) {

            logger.error("User unauthorized to check OTP valid");
            systemRecorder.recordError("IS_OTP_VALID.FAILED", ErrorSeverity.ERROR, "ENTITY_MANAGEMENT", "END_USER", ErrorMessages.SECURITY_VIOLATION_EXCEPTION);

            throw new SecurityViolationException(ErrorMessages.SECURITY_VIOLATION_EXCEPTION);
        }

    }

    private void authorizeImportEntities(final EntityType entityType) {

        if (!(contextUtility.isCredMOperation() || contextUtility.isNSCSOperation())) {

            if (entityType == EntityType.CA_ENTITY) {
                logger.debug("Authorize import caentities");
                caEntityAuthorizationHandler.authorizeImportEntities();
            } else {
                logger.debug("Authorize import entities");
                entityAuthorizationHandler.authorizeImportEntities();
            }

        }

    }

    private void authorizeCreateEntity(final EntityType entityType) {

        if (!(contextUtility.isCredMOperation() || contextUtility.isNSCSOperation())) {

            if (entityType == EntityType.CA_ENTITY) {
                logger.debug("Authorizing creation of CAEntity");
                caEntityAuthorizationHandler.authorizeCreateEntity();
            } else {
                logger.debug("Authorizing creation of End Entity");
                entityAuthorizationHandler.authorizeCreateEntity();
            }
        }
    }

    private void authorizeGetEntity(final EntityType entityType) {

        if (!(contextUtility.isCredMOperation() || contextUtility.isNSCSOperation())) {

            if (entityType == EntityType.CA_ENTITY) {
                logger.debug("Authorizing listing of CAEntity");
                caEntityAuthorizationHandler.authorizeReadEntity();
            } else {
                logger.debug("Authorizing listing of End Entity");
                entityAuthorizationHandler.authorizeReadEntity();
            }
        }
    }

    private void authorizeUpdateEntity(final EntityType entityType) {

        if (!(contextUtility.isCredMOperation() || contextUtility.isNSCSOperation())) {

            if (entityType == EntityType.CA_ENTITY) {
                logger.debug("Authorizing updation of CAEntity");
                caEntityAuthorizationHandler.authorizeUpdateEntity();
            } else {
                logger.debug("Authorizing updation of End Entity");
                entityAuthorizationHandler.authorizeUpdateEntity();
            }
        }
    }

    private void authorizeDeleteEntity(final EntityType entityType) {

        if (!contextUtility.isNSCSOperation()) {

            if (entityType == EntityType.CA_ENTITY) {
                logger.debug("Authorizing deletion of CAEntity");
                caEntityAuthorizationHandler.authorizeDeleteEntity();
            } else {
                logger.debug("Authorizing deletion of End Entity");
                entityAuthorizationHandler.authorizeDeleteEntity();
            }
        }
    }

}
