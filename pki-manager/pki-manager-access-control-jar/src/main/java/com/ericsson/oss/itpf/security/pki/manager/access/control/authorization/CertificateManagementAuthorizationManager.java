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
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.certificate.CACertificateManagementAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.certificate.EntityCertificateManagementAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.utils.ContextUtility;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;

/**
 * This class is used to authorize Certificate management operations.
 * 
 * @author tcsvath
 * 
 */
public class CertificateManagementAuthorizationManager {

    @Inject
    CACertificateManagementAuthorizationHandler caCertificateManagementAuthorizationHandler;

    @Inject
    EntityCertificateManagementAuthorizationHandler entityCertificateManagementAuthorizationHandler;

    @Inject
    private ContextUtility contextUtility;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    Logger logger;

    /**
     * Method is used to authorize Certificate Management operations.
     * 
     * @param actionType
     *            Action of type {@link ActionType}
     * @param entityType
     *            entity type {@link EntityType}
     */
    public void authorizeCertificateMgmtOperations(final ActionType actionType, final EntityType entityType) {
        switch (actionType) {
        case CREATE:
            authorizeGenerateCetificate(entityType);
            break;
        case UPDATE:
            authorizeUpdateCertificate(entityType);
            break;
        case READ:
            authorizeGetCertificate(entityType);
            break;
        default:
            logger.error("Invalid Certificate Management Operations {} " , actionType);
            throw new IllegalArgumentException("Invalid Certificate Management Operations " + actionType);
        }

    }

    /**
     * Method used to authorize get trust certificates.
     */
    public void authorizeGetTrustCertificates() {

        if (!contextUtility.isNSCSOperation()) {

            logger.error("User unauthorized for list of trust certificates");
            systemRecorder.recordError("LIST_OF_TRUST_CERTIFICATES.FAILED", ErrorSeverity.ERROR, "CERTIFICATE_MANAGEMENT", "END_USER", ErrorMessages.SECURITY_VIOLATION_EXCEPTION);

            throw new SecurityViolationException(ErrorMessages.SECURITY_VIOLATION_EXCEPTION);

        }

    }

    /**
     * Method used to authorize generate Certificate.
     */
    private void authorizeGenerateCetificate(final EntityType entityType) {

        if (!contextUtility.isCredMOperation()) {

            if (entityType == EntityType.CA_ENTITY) {
                logger.debug("Authorize generate certificate for CAEntity");
                caCertificateManagementAuthorizationHandler.authorizeGenerateCertificate();
            } else {
                logger.debug("Authorize generate certificate for Entity");
                entityCertificateManagementAuthorizationHandler.authorizeGenerateCertificate();
            }
        }
    }

    /**
     * Method used to authorize update Certificate.
     */
    private void authorizeUpdateCertificate(final EntityType entityType) {

        if (entityType == EntityType.CA_ENTITY) {
            logger.debug("Authorize update certificate for CAEntity");
            caCertificateManagementAuthorizationHandler.authorizeUpdateCertificate();
        } else {
            logger.debug("Authorize update certificate for Entity");
            entityCertificateManagementAuthorizationHandler.authorizeUpdateCertificate();
        }

    }

    /**
     * Method used to authorize get Certificate.
     */
    private void authorizeGetCertificate(final EntityType entityType) {

        if (entityType == EntityType.CA_ENTITY) {
            if (!(contextUtility.isCredMOperation() || contextUtility.isNSCSOperation())) {
                logger.debug("Authorize get certificate for CAEntity");
                caCertificateManagementAuthorizationHandler.authorizeGetCertificate();
            }

        } else {
            logger.debug("Authorize get certificate for Entity");
            if (!(contextUtility.isCredMOperation() || contextUtility.isNSCSOperation())) {
                entityCertificateManagementAuthorizationHandler.authorizeGetCertificate();
            }

        }

    }

    /**
     * This method is used to call a method which checks user authorization for generating Certificate for Security Gateway.
     */
    public void authorizeGenerateSecGwCertificate() {
        logger.debug("Authorize user for generate SecGw Certificate operation");
        entityCertificateManagementAuthorizationHandler.authorizeGenerateSecGwCertificate();
    }

}
