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

import java.security.cert.X509Certificate;
import java.util.Set;

import javax.inject.Inject;

import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidAuthorityKeyIdentifierExtension;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CertificateExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class is used to validate AuthoritKeyIdentifier of the imported certificate.
 * 
 * @author tcsramc
 *
 */
public class X509CertificateAuthorityKeyIdentifierValidator implements CommonValidator<CACertificateValidationInfo> {

    @Inject
    Logger logger;

    @Inject
    CertificateExtensionUtils certificateExtensionUtils;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo cACertificateValidationInfo) throws ValidationException {
        validateAuthorityKeyIdentifier(cACertificateValidationInfo.getCaName(), cACertificateValidationInfo.getCertificate());
    }

    public void validateAuthorityKeyIdentifier(final String caName, final X509Certificate x509Certificate) throws InvalidAuthorityKeyIdentifierExtension, MissingMandatoryFieldException {
        logger.debug("Validating X509Certificate AuthorityKeyIdentifier for CA {} ", caName);

        final byte[] extensionValue = certificateExtensionUtils.getCertificateAttributeExtensionValue(x509Certificate, Extension.authorityKeyIdentifier.getId());
        final Set<String> criticalExtensionOIDs = x509Certificate.getCriticalExtensionOIDs();
        isExtensionCritical(criticalExtensionOIDs, caName);

        isKeyIdentifierOctectString(extensionValue, caName);

    }

    private void isExtensionCritical(final Set<String> criticalExtensionOIDs, final String caName) throws InvalidAuthorityKeyIdentifierExtension {

        if (criticalExtensionOIDs.contains(Extension.authorityKeyIdentifier.getId())) {
            logger.error(" AuthorityKeyIdentifier Extension: " + ErrorMessages.EXTENSION_NON_CRITICAL + "for CA {} ", caName);
            throw new InvalidAuthorityKeyIdentifierExtension(" AuthorityKeyIdentifier Extension: " + ErrorMessages.EXTENSION_NON_CRITICAL);
        }
    }

    private void isKeyIdentifierOctectString(final byte[] extensionValue, final String caName) throws InvalidAuthorityKeyIdentifierExtension {
        final byte[] octets = (ASN1OctetString.getInstance(extensionValue).getOctets());
        if (octets.length == 0) {
            logger.error(ErrorMessages.OCTECT_VALUE_NULL + "for CA {} ", caName);
            throw new InvalidAuthorityKeyIdentifierExtension(ErrorMessages.OCTECT_VALUE_NULL);
        }
    }

}
