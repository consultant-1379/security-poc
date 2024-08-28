/*------------------------------------------------------------------------------
 *******************************************************************************
a * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.InvalidOperationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateGenerationInfoData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

public class CertificateGenerationInfoValidator implements CommonValidator<CACertificateValidationInfo> {

    @Inject
    Logger logger;

    @Inject
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo caCertificateValidationInfo) throws ValidationException {
        validateCertificateGenerationInfo(caCertificateValidationInfo.getCaName());
    }

    private void validateCertificateGenerationInfo(final String caName) throws CertificateServiceException, InvalidOperationException {
        logger.debug("Validating CertificateGenerationInfo  for CA{}", caName);

        final CertificateGenerationInfoData certificateGenerationInfoData = caCertificatePersistenceHelper.getLatestCertificateGenerationInfo(caName);
        if (certificateGenerationInfoData == null || certificateGenerationInfoData.getCertificateRequestData() == null) {
            logger.error(ErrorMessages.CSR_NOT_FOUND + " for CA {} " , caName);
            throw new InvalidOperationException(ErrorMessages.CSR_NOT_FOUND);
        }

    }

}
