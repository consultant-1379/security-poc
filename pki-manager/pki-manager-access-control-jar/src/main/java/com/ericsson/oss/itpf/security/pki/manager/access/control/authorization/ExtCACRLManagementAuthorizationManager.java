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
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.crl.ExtCACRLManagementAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.utils.ContextUtility;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;

/**
 * This class is used to authorize external CA operations including both {@link ExtCA}
 * 
 * 
 */
public class ExtCACRLManagementAuthorizationManager {

    @Inject
    private Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    private ExtCACRLManagementAuthorizationHandler externalCACRLAuthorizationHandler;

    @Inject
    ContextUtility contextUtility;

    /**
     * Method is used to authorize external CRL info operations.
     * 
     * @param actionType
     *            Action of type {@link ActionType}
     */
    public void authorizeExternalCRLOperations(final ActionType actionType) {
        if (actionType != null) {
            switch (actionType) {

            case UPDATE:
                authorizeUpdateExternalCA();
                break;
            case EXPORT:
            case CREATE:
            case READ:
            case DELETE:
            default:
                logger.error("Invalid external CA operation {} " , actionType);
                throw new IllegalArgumentException("Invalid external CA operation " + actionType);
            }
        }
    }

    /**
     * Method is used to authorize external CRL info operations.
     * 
     * @param actionType
     *            Action of type {@link ActionType}
     */
    public void authorizeExternalCRLInfoOperations(final ActionType actionType) {

        if (actionType != null) {
            switch (actionType) {
            case READ:
                authorizeGetExternalCRLInfo();
                break;
            case DELETE:
                authorizeDeleteExternalCRLInfo();
                break;
            case UPDATE:
                authorizeUpdateExternalCRLInfo();
                break;
            default:
                logger.error("Invalid external CA operation {} " , actionType);
                throw new IllegalArgumentException("Invalid external CA operation " + actionType);
            }
        }
    }

    /**
     * Method is used to authorize external CRL name available check.
     */
    public void authorizeIsExternalCANameAvailable() {
        if (!(contextUtility.isCredMOperation())) {
            logger.error("User unauthorized to Is External CAName Available");
            systemRecorder.recordError("IS_EXTERNAL_CANAME_AVAILALE.FAILED", ErrorSeverity.ERROR, "EXTCA_MANAGEMENT", "END_USER", ErrorMessages.SECURITY_VIOLATION_EXCEPTION);
            throw new SecurityViolationException(ErrorMessages.SECURITY_VIOLATION_EXCEPTION);
        }
    }

    /**
     * 
     */
    private void authorizeUpdateExternalCA() {
        if (!(contextUtility.isCredMOperation())) {
            logger.debug("Authorize update external CA");
            externalCACRLAuthorizationHandler.authorizeUpdateExternalCA();
        }
    }

    /**
     * 
     */
    private void authorizeGetExternalCRLInfo() {
        if (!(contextUtility.isCredMOperation())) {
            logger.debug("Authorize read external CRL info");
            externalCACRLAuthorizationHandler.authorizeGetExternalCRLInfo();
        }
    }

    /**
     * 
     */
    private void authorizeDeleteExternalCRLInfo() {
        if (!(contextUtility.isCredMOperation())) {
            logger.debug("Authorize delete external CRL info");
            externalCACRLAuthorizationHandler.authorizeDeleteExternalCRLInfo();
        }
    }

    /**
     * 
     */
    private void authorizeUpdateExternalCRLInfo() {
        if (!(contextUtility.isCredMOperation())) {
            logger.debug("Authorize update external CRL info");
            externalCACRLAuthorizationHandler.authorizeUpdateExternalCA();
        }
    }
}
