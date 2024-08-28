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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.validator;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidOperationException;

/**
 * Validates given CA for import certificate.
 * 
 */
public class ImportCertificateCAValidator {

    @Inject
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Inject
    Logger logger;

    @Inject
    SystemRecorder systemRecorder;

    /**
     * Validates given CA is a Root CA and Active or not.
     * 
     * @param caName
     *            name of the CA.
     * @throws CoreEntityNotFoundException
     *             In case of entity not found in the system.
     * @throws CoreEntityServiceException
     *             In case of db errors for entity in the system.
     * @throws InvalidCAException
     *             Thrown in case Root CA is not active.
     * @throws InvalidOperationException
     *             Thrown in case given CA is not Root CA.
     */
    public void validate(final String caName) throws CoreEntityNotFoundException, CoreEntityServiceException, InvalidCAException, InvalidOperationException {

        final CertificateAuthorityData certificateAuthorityData = certificatePersistenceHelper.getCA(caName);
        logger.debug("Validating certificate authority data for CA entity : {}", caName);
        if (!certificateAuthorityData.isRootCA()) {
            logger.error("{}: {}", ErrorMessages.CA_IS_NOT_ROOT_CA, caName);
            systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "ImportCertificateCAValidator", "caName", "Given CA entity : "
                    + caName + " is not a ROOT CA");
            throw new InvalidOperationException(ErrorMessages.CA_IS_NOT_ROOT_CA);
        }
        if (certificateAuthorityData.getStatus() != CAStatus.NEW && certificateAuthorityData.getStatus() != CAStatus.ACTIVE) {
            logger.error("{}: {}", ErrorMessages.CA_NEW_OR_ACTIVE, caName);
            systemRecorder.recordError("PKICore.CertificateManagement", ErrorSeverity.ERROR, "ImportCertificateCAValidator", "caName", "Given CA entity : "
                    + caName + " status should be ACTIVE or NEW");
            throw new InvalidCAException(ErrorMessages.CA_NEW_OR_ACTIVE);
        }
    }
}
