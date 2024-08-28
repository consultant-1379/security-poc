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
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.configuration.ConfigurationManagementAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.utils.ContextUtility;

/**
 * This class is used to authorize Configuration management operations.
 * 
 * @author tcsvath
 * 
 */
public class ConfigurationManagementAuthorizationManager {

    @Inject
    ConfigurationManagementAuthorizationHandler configurationManagementAuthorizationHandler;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    private ContextUtility contextUtility;

    @Inject
    Logger logger;

    /**
     * Method is used to authorize configuration Management operations.
     * 
     * @param actionType
     *            Action of type {@link ActionType}
     */
    public void authorizeAlgorithmConfigurationOperations(final ActionType actionType) {

        switch (actionType) {
        case READ:
            authorizeGetAlgorithm();
            break;
        case UPDATE:
            authorizeUpdateAlgorithm();
            break;
        default:
            logger.error("Invalid Algorithm Configuration Operation {} " , actionType);
            throw new IllegalArgumentException("Invalid Algorithm Configuration Operation " + actionType);
        }

    }

    /**
     * Method used to authorize isCategoryNameAvailable.
     */
    public void authorizeIsCategoryNameAvailable() {

        if (!contextUtility.isCredMOperation()) {

            logger.error("User unauthorized to check category name available or not");
            systemRecorder.recordError("IS_CATEGORY_NAME_AVAILABLE.FAILED", ErrorSeverity.ERROR, "CONFIGURATION_MANAGEMENT", "END_USER", ErrorMessages.SECURITY_VIOLATION_EXCEPTION);

            throw new SecurityViolationException(ErrorMessages.SECURITY_VIOLATION_EXCEPTION);

        }

    }

    private void authorizeGetAlgorithm() {
        logger.debug("Authorize list of algorithms");
        configurationManagementAuthorizationHandler.authorizeGetAlgorithm();

    }

    private void authorizeUpdateAlgorithm() {

        logger.debug("Authorize update algorithm");
        configurationManagementAuthorizationHandler.authorizeUpdateAlgorithm();

    }

    /**
     * Method is used to authorize entity category operations.
     * 
     * @param actionType
     *            Action of type {@link ActionType}
     */
    public void authorizeEntityCategoryOperations(final ActionType actionType) {

        switch (actionType) {
        case CREATE:
            authorizeCreateEntityCategory();
            break;
        case UPDATE:
            authorizeUpdateEntityCategory();
            break;
        case DELETE:
            authorizeDeleteEntityCategory();
            break;
        case READ:
            authorizeGetEntityCategory();
            break;
        default:
            logger.error("Invalid Action Type {} " , actionType);
            throw new IllegalArgumentException("Invalid Action Type " + actionType);
        }
    }

    private void authorizeCreateEntityCategory() {

        if (!contextUtility.isCredMOperation()) {
            logger.debug("Authorize create entity category");
            configurationManagementAuthorizationHandler.authorizeCreateEntityCategory();
        }

    }

    private void authorizeUpdateEntityCategory() {

        logger.debug("Authorize update entity category");
        configurationManagementAuthorizationHandler.authorizeUpdateEntityCategory();

    }

    private void authorizeDeleteEntityCategory() {

        logger.debug("Authorize delete entity category");
        configurationManagementAuthorizationHandler.authorizeDeleteEntityCategory();

    }

    private void authorizeGetEntityCategory() {

        if (!contextUtility.isNSCSOperation()) {
            logger.debug("Authorize listing/get entity categories");
            configurationManagementAuthorizationHandler.authorizeGetEntityCategory();
        }

    }

    /**
     * Method is used to authorize entity category operations.
     * 
     * @param actionType
     *            Action of type {@link ActionType}
     */
    public void authorizeCustomConfigurationOperations(final ActionType actionType) {

        switch (actionType) {
        case CREATE:
            authorizeCreateCustomConfiguration();
            break;
        case UPDATE:
            authorizeUpdateCustomConfiguration();
            break;
        case DELETE:
            authorizeDeleteCustomConfiguration();
            break;
        case READ:
            authorizeGetCustomConfiguration();
            break;
        default:
            logger.error("Invalid Action Type {} " , actionType);
            throw new IllegalArgumentException("Invalid Action Type " + actionType);
        }
    }

    /**
     * 
     */
    public void authorizeGetCustomConfiguration() {
        if (!(contextUtility.isCredMOperation() || contextUtility.isNSCSOperation())) {
            logger.error("User unauthorized to retrieve custom configuration");
            throw new SecurityViolationException(ErrorMessages.SECURITY_VIOLATION_EXCEPTION);
        }
    }

    /**
     * 
     */
    public void authorizeUpdateCustomConfiguration() {
        if (!(contextUtility.isCredMOperation() || contextUtility.isNSCSOperation())) {
            logger.error("User unauthorized to update custom configuration");
            throw new SecurityViolationException(ErrorMessages.SECURITY_VIOLATION_EXCEPTION);
        }
    }

    /**
     * 
     */
    public void authorizeCreateCustomConfiguration() {
        if (!(contextUtility.isCredMOperation() || contextUtility.isNSCSOperation())) {
            logger.error("User unauthorized to create custom configuration");
            throw new SecurityViolationException(ErrorMessages.SECURITY_VIOLATION_EXCEPTION);
        }
    }

    /**
     * 
     */
    public void authorizeDeleteCustomConfiguration() {
        if (!(contextUtility.isCredMOperation() || contextUtility.isNSCSOperation())) {
            logger.error("User unauthorized to delete custom configuration");
            throw new SecurityViolationException(ErrorMessages.SECURITY_VIOLATION_EXCEPTION);
        }
    }

    /**
     *
     */
    public void authorizeIsPresentCustomConfiguration() {
        if (!(contextUtility.isCredMOperation() || contextUtility.isNSCSOperation())) {

            logger.error("User unauthorized to check custom configuration available or not");
            throw new SecurityViolationException(ErrorMessages.SECURITY_VIOLATION_EXCEPTION);

        }
    }
}
