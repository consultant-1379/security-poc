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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.rfc;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.*;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateRevokedException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.ExternalCRLInfoData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class is used to perform crl validation for the given certificate.
 * 
 * @author tcsramc
 *
 */
public class X509CertificateCRLValidator implements CommonValidator<CACertificateValidationInfo> {

    @Inject
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Inject
    Logger logger;

    public static final String CA_SUBJECT_NAME_PATH = "certificateAuthorityData.subjectDN";

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo cACertificateValidationInfo) throws ValidationException {
        validateCertificateCRL(cACertificateValidationInfo.getCaName(), cACertificateValidationInfo.getCertificate());
    }

    private void validateCertificateCRL(final String caName, final X509Certificate x509Certificate) throws CANotFoundException, CertificateGenerationException, CertificateRevokedException,
            InvalidCAException {
        logger.debug("Validating X509Certificate CRL for CA {} ", caName);
        try {
            final String issuerDN = x509Certificate.getIssuerDN().getName();
            final CAEntityData caEntityData = getCAEntityData(issuerDN, caName);

            final byte[] issuercRL = getIssuerCRL(caEntityData, caName);

            final X509CRL issuerX509CRL = getIssuerX509CRL(issuercRL, caName);
            if (issuerX509CRL.isRevoked(x509Certificate)) {
                logger.error(ErrorMessages.CERTIFICATE_ALREADY_REVOKED + "Serial Number: {}", x509Certificate.getSerialNumber() + " Issuer Name: {}", caName);
                throw new CertificateRevokedException(ErrorMessages.CERTIFICATE_ALREADY_REVOKED + "Serial Number is{}" + x509Certificate.getSerialNumber());
            }
        } catch (final IOException iOException) {
            logger.debug("Exception occured while reading input Stream for CA {} ",caName, iOException);
            logger.error(ErrorMessages.IO_EXCEPTION, "  for CA {} ", caName);
            throw new CertificateRevokedException(ErrorMessages.IO_EXCEPTION);
        }
    }

    private CAEntityData getCAEntityData(final String issuerDN, final String caName) throws InvalidCAException, CANotFoundException {
        final CAEntityData caEntityData;
        caEntityData = caCertificatePersistenceHelper.getCAEntity(issuerDN, CA_SUBJECT_NAME_PATH);
        if (caEntityData == null) {
            logger.error(ErrorMessages.CA_ENTITY_NOT_FOUND, "for CA {} ", caName);
            throw new CANotFoundException(ErrorMessages.CA_ENTITY_NOT_FOUND);
        }
        if (!caEntityData.isExternalCA()) {
            logger.error(ErrorMessages.CA_IS_NOT_EXTERNAL_CA, "for CA {} ", caName);
            throw new InvalidCAException(ErrorMessages.CA_IS_NOT_EXTERNAL_CA);
        }
        return caEntityData;
    }

    private byte[] getIssuerCRL(final CAEntityData caEntityData, final String caName) throws com.ericsson.oss.itpf.security.pki.manager.exception.CRLException {
        final ExternalCRLInfoData externalCRLInfoData = caEntityData.getCertificateAuthorityData().getExternalCrlInfoData();
        if (externalCRLInfoData == null) {
            logger.error(ErrorMessages.EXTERNAL_CA_CRL_INFO_EMPTY, "for CA {} ", caName);
            throw new com.ericsson.oss.itpf.security.pki.manager.exception.CRLException(ErrorMessages.EXTERNAL_CA_CRL_INFO_EMPTY);
        }
        final byte[] cRL = externalCRLInfoData.getCrl();
        if (cRL == null) {
            logger.error(ErrorMessages.EXTERNAL_CA_CRL_EMPTY, "for CA {} ", caName);
            throw new com.ericsson.oss.itpf.security.pki.manager.exception.CRLException(ErrorMessages.EXTERNAL_CA_CRL_EMPTY);
        }
        return cRL;
    }

    private X509CRL getIssuerX509CRL(final byte[] cRL, final String caName) throws CertificateGenerationException, CRLGenerationException, IOException {
        X509CRL x509cRL = null;
        ByteArrayInputStream crlInputStream = null;
        try {
            crlInputStream = new ByteArrayInputStream(cRL);
            final CertificateFactory certificateFactory = CertificateFactory.getInstance("X509");
            x509cRL = (X509CRL) certificateFactory.generateCRL(crlInputStream);
        } catch (CertificateException certificateException) {
            logger.error(ErrorMessages.CERTIFICATE_FACTORY_NOT_FOUND, "for CA {} ", caName, certificateException.getMessage());
            throw new CertificateGenerationException(ErrorMessages.CERTIFICATE_FACTORY_NOT_FOUND, certificateException);

        } catch (CRLException cRLExcpetion) {
            logger.error(ErrorMessages.FAIL_TO_GENERATE_CRL, "for CA {} ", caName, cRLExcpetion.getMessage());
            throw new CertificateGenerationException(ErrorMessages.FAIL_TO_GENERATE_CRL, cRLExcpetion);

        } finally {
            if (crlInputStream != null) {
                crlInputStream.close();
            }
        }
        return x509cRL;
    }
}
