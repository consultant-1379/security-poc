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

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;

import javax.inject.Inject;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateConversionException;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.ExtCACertificatePersistanceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidAuthorityKeyIdentifierExtension;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class is used to validate Imported Certificate Authority Key Identifier with Issuer certificate SubjectKeyIdentifier.
 * 
 * @author tcsramc
 *
 */
public class AuthorityKeyIdentifierValidator implements CommonValidator<CACertificateValidationInfo> {

    @Inject
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Inject
    ExtCACertificatePersistanceHandler extCACertificatePersistanceHandler;

    @Inject
    Logger logger;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo cACertificateValidationInfo) throws ValidationException {
        // Validates Certificate's Authority key identifier extension with its issuer Subject key identifier extension.
        validateCertificateAuthorityKeyIdentifier(cACertificateValidationInfo.getCertificate(), cACertificateValidationInfo.getCaName());
    }

    private void validateCertificateAuthorityKeyIdentifier(final X509Certificate certificate, final String caName) throws CertificateNotFoundException, CertificateServiceException,
            InvalidAuthorityKeyIdentifierExtension {

        try {
            // get External CA certificate which signed imported certificate.
            final X500Name issuerDn = new JcaX509CertificateHolder(certificate).getIssuer();
            logger.debug("Validating X509Certificate and Issuer {}", issuerDn);

            final X509Certificate extCACertificate = extCACertificatePersistanceHandler.getIssuerX509Certificate(certificate);

            final byte[] authorityKeyIdOfCert = certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
            final ASN1OctetString akiOctectString = ASN1OctetString.getInstance(authorityKeyIdOfCert);
            final AuthorityKeyIdentifier authorityKeyIdentifier = AuthorityKeyIdentifier.getInstance(akiOctectString.getOctets());

            final byte[] subjectKeyIdOfIssuerCert = extCACertificate.getExtensionValue(Extension.subjectKeyIdentifier.getId());
            final ASN1OctetString skiOctectString = ASN1OctetString.getInstance(subjectKeyIdOfIssuerCert);
            final SubjectKeyIdentifier subjectKeyIdentifier = SubjectKeyIdentifier.getInstance(skiOctectString.getOctets());

            validateAuthorityKeyIdWithSubjectKeyIdOfIssuer(authorityKeyIdentifier.getKeyIdentifier(), subjectKeyIdentifier.getKeyIdentifier(), caName);

        } catch (CertificateEncodingException certificateEncodingException) {
            logger.error(ErrorMessages.CERTIFICATE_ENCODING_FAILED, " for CA {} ", caName, certificateEncodingException.getMessage());
            throw new InvalidAuthorityKeyIdentifierExtension(ErrorMessages.CERTIFICATE_ENCODING_FAILED, certificateEncodingException);
        } catch (CertificateConversionException certificateConversionException) {
            logger.error(ErrorMessages.CERTIFICATE_ENCODING_FAILED, " for CA {} ", caName, certificateConversionException.getMessage());
            throw new InvalidAuthorityKeyIdentifierExtension(ErrorMessages.CERTIFICATE_ENCODING_FAILED, certificateConversionException);
        }
    }

    private void validateAuthorityKeyIdWithSubjectKeyIdOfIssuer(final byte[] authorityKeyIdOfCert, final byte[] subjectKeyIdOfIssuerCert, final String caName)
            throws InvalidAuthorityKeyIdentifierExtension {
        if (!(java.util.Arrays.equals(authorityKeyIdOfCert, subjectKeyIdOfIssuerCert))) {
            logger.error(ErrorMessages.AUTHORITY_KEY_VALIDATION_FAILED, " for CA {} ", caName);
            throw new InvalidAuthorityKeyIdentifierExtension(ErrorMessages.AUTHORITY_KEY_VALIDATION_FAILED);
        }
    }

}