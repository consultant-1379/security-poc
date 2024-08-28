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

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.HashSet;

import javax.inject.Inject;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

public class X509CertificateExtensionValidator implements CommonValidator<CACertificateValidationInfo> {

    @Inject
    Logger logger;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo cACertificateValidationInfo) throws ValidationException {
        validateCertificateExtensions(cACertificateValidationInfo.getCaName(), cACertificateValidationInfo.getCertificate());
    }

    public void validateCertificateExtensions(final String caName, final X509Certificate x509Certificate) throws MissingMandatoryFieldException {
        logger.debug("Validating X509Certificate CertificateExtension for CA {} ", caName);
        try {
            final Extensions extensions = new JcaX509CertificateHolder(x509Certificate).getExtensions();
            if (extensions != null) {

                checkForDuplicateExtensions(caName, extensions);

            }
        } catch (CertificateEncodingException certificateEncodingException) {
            logger.error(ErrorMessages.CERTIFICATE_ENCODING_FAILED, "for CA {} ", caName, certificateEncodingException.getMessage());
            throw new MissingMandatoryFieldException(ErrorMessages.CERTIFICATE_ENCODING_FAILED, certificateEncodingException);
        }
    }

    private void checkForDuplicateExtensions(final String caName, final Extensions extensions) throws MissingMandatoryFieldException {
        final HashSet<ASN1ObjectIdentifier> aSN1ObjectIdentifierSet = new HashSet<ASN1ObjectIdentifier>();

        for (final ASN1ObjectIdentifier extensionAsn1ObjectIdentifier : extensions.getExtensionOIDs()) {
            if (!aSN1ObjectIdentifierSet.add(extensionAsn1ObjectIdentifier)) {
                logger.error(ErrorMessages.CERTIFICATE_EXTENSION_VALIDATION_FAILED + "for CA {} ", caName);
                throw new MissingMandatoryFieldException(ErrorMessages.CERTIFICATE_EXTENSION_VALIDATION_FAILED);
            }
        }
    }
}
