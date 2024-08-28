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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.csr;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.InvalidOperationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.KeyPairGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CAValidationInfo;

/**
 * This class handles the CA validations(1. isRootCA or not 2. given Entity is active or not).
 * 
 * @author tcsramc
 *
 */
public class CAValidator implements CommonValidator<CAValidationInfo> {

    @Inject
    Logger logger;

    @Inject
    SystemRecorder systemRecorder;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CAValidationInfo caValidationInfo) throws ValidationException {

        validateRootCA(caValidationInfo);
    }

    private void validateRootCA(final CAValidationInfo caValidationInfo) throws InvalidCAException, InvalidOperationException, KeyPairGenerationException {
        final CAEntity caEntity = caValidationInfo.getCaEntity();
        final boolean newKey = caValidationInfo.isNewKey();

        final String rootCAName = caEntity.getCertificateAuthority().getName();
        logger.debug("Validating RootCA for CA Name {}", rootCAName);
        if (!(caEntity.getCertificateAuthority().isRootCA())) {
            logger.error(rootCAName, ErrorMessages.NOT_ROOT_CA, " for CA {} ", rootCAName);
            systemRecorder.recordError("PKI_MANAGER.EXPORT_CSR_FAIL", ErrorSeverity.ERROR, "ExportCSRHandler", "ExportCSR", rootCAName + ErrorMessages.NOT_ROOT_CA);
            throw new InvalidOperationException(ErrorMessages.NOT_ROOT_CA);
        }

        if ((caEntity.getCertificateAuthority().getStatus() == CAStatus.INACTIVE) && !newKey) {
            throw new KeyPairGenerationException(ErrorMessages.INVALID_KEY_REQUEST_FOR_INACTIVE_CA);
        }

        if (caEntity.getCertificateAuthority().getStatus() == CAStatus.DELETED) {
            logger.error(ErrorMessages.INACTIVE_CA + " for CA {} ", rootCAName);
            systemRecorder.recordError("PKI_MANAGER.EXPORT_CSR_FAIL", ErrorSeverity.ERROR, "ExportCSRHandler", "ExportCSR", rootCAName + ErrorMessages.INACTIVE_CA);
            throw new InvalidCAException(ErrorMessages.INACTIVE_CA);
        }
    }

}
