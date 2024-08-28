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
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.profile.ExternalCAAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.utils.ContextUtility;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;

/**
 * This class is used to authorize external CA operations including both {@link ExtCA}
 * 
 * 
 */
public class ExternalCAManagementAuthorizationManager {

    @Inject
    private Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    private ExternalCAAuthorizationHandler externalCAEntityAuthorizationHandler;

    @Inject
    ContextUtility contextUtility;

    /**
     * Method is used to authorize external CA operations.
     * 
     * @param actionType
     *            Action of type {@link ActionType}
     */
    public void authorizeExternalCAOperations(final ActionType actionType) {

        if (actionType != null) {
            switch (actionType) {
            case EXPORT:
                authorizeExportExternalCACeritifcate();
                break;
            case CREATE:
                authorizeCreateExternalCA();
                break;
            case UPDATE:
                authorizeUpdateExternalCA();
                break;
            case READ:
                authorizeGetExternalCA();
                break;
            case DELETE:
                authorizeDeleteExternalCA();
                break;
            default:
                logger.error("Invalid external CA operation {} " , actionType);
                throw new IllegalArgumentException("Invalid external CA operation " + actionType);
            }
        }
    }

    /**
     * Method is used to authorize entity name available check.
     */
    public void authorizeIsExternalCANameAvailable() {
        if (!(contextUtility.isCredMOperation() || contextUtility.isNSCSOperation())) {
            logger.error("User unauthorized to Is External CAName Available");
            systemRecorder.recordError("IS_EXTERNAL_CANAME_AVAILALE.FAILED", ErrorSeverity.ERROR, "EXTCA_MANAGEMENT", "END_USER", ErrorMessages.SECURITY_VIOLATION_EXCEPTION);
            throw new SecurityViolationException(ErrorMessages.SECURITY_VIOLATION_EXCEPTION);
        }
    }

    /**
     * 
     */
    private void authorizeDeleteExternalCA() {
        if (!(contextUtility.isCredMOperation() || contextUtility.isNSCSOperation())) {
            logger.debug("Authorize delete external CA");
            externalCAEntityAuthorizationHandler.authorizeDeleteExternalCA();
        }
    }

    /**
     * 
     */
    private void authorizeGetExternalCA() {
        if (!(contextUtility.isCredMOperation() || contextUtility.isNSCSOperation())) {
            logger.debug("Authorize read external CA");
            externalCAEntityAuthorizationHandler.authorizeGetExternalCA();
        }
    }

    /**
     * 
     */
    private void authorizeUpdateExternalCA() {
        if (!(contextUtility.isCredMOperation() || contextUtility.isNSCSOperation())) {
            logger.debug("Authorize update external CA");
            externalCAEntityAuthorizationHandler.authorizeUpdateExternalCA();
        }
    }

    /**
     * 
     */
    private void authorizeCreateExternalCA() {
        if (!(contextUtility.isCredMOperation() || contextUtility.isNSCSOperation())) {
            logger.debug("Authorize create external CA");
            externalCAEntityAuthorizationHandler.authorizeCreateExternalCA();
        }
    }

    /**
     * 
     */
    private void authorizeExportExternalCACeritifcate() {
        if (!(contextUtility.isCredMOperation() || contextUtility.isNSCSOperation())) {
            logger.debug("Authorize export certificate for external CA");
            externalCAEntityAuthorizationHandler.authorizeExportExternalCACeritifcate();
        }
    }

}
