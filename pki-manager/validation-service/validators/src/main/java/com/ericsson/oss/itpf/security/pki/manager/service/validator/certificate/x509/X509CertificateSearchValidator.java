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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509;

import java.security.cert.X509Certificate;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class is used to verify whether the certificate to import is already present in the database or not.
 * 
 * @author tcsramc
 *
 */
public class X509CertificateSearchValidator implements CommonValidator<CACertificateValidationInfo> {

    @Inject
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Inject
    Logger logger;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo cACertificateValidationInfo) throws ValidationException {
        validateX509Certificate(cACertificateValidationInfo.getCaName(), cACertificateValidationInfo.getCertificate());
    }

    private void validateX509Certificate(final String caName, final X509Certificate x509Certificate) throws CertificateAlreadyExistsException {
        logger.debug("Validating X509Certificate for the given issuer in the database, serialNumber{} issuerName{} ", x509Certificate.getSerialNumber(), caName);
        try {
            final int certifiateCount = caCertificatePersistenceHelper.getCertificatesCount(caName, Long.toHexString(x509Certificate.getSerialNumber().longValue()));
            if (certifiateCount != 0) {
                logger.error(ErrorMessages.CERTIFICATE_ALREADY_PRESENT + " for CA and Serial Number is : {}", caName, x509Certificate.getSerialNumber());
                throw new CertificateAlreadyExistsException(ErrorMessages.CERTIFICATE_ALREADY_PRESENT);
            }
        } catch (final PersistenceException persistenceException) {
            logger.error(ErrorMessages.INTERNAL_ERROR, persistenceException.getMessage());
            throw new CertificateAlreadyExistsException(ErrorMessages.INTERNAL_ERROR, persistenceException);
        }
    }
}
