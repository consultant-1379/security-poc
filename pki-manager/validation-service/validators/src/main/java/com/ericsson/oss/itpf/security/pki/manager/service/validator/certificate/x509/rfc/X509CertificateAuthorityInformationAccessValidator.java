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

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import javax.inject.Inject;

import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.x509.extension.X509ExtensionUtil;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidAuthorityInformationAccessExtension;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CertificateExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class is used to validate AuthorityInformationAccessValidator for the imported certificate.
 * 
 * @author tcsramc
 *
 */
public class X509CertificateAuthorityInformationAccessValidator implements CommonValidator<CACertificateValidationInfo> {

    @Inject
    private Logger logger;

    @Inject
    CertificateExtensionUtils certificateExtensionUtils;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo cACertificateValidationInfo) throws ValidationException {
        validateAuthorityInformationAccess(cACertificateValidationInfo.getCaName(), cACertificateValidationInfo.getCertificate());
    }

    private void validateAuthorityInformationAccess(final String caName, final X509Certificate x509Certificate) throws InvalidAuthorityInformationAccessExtension {
        logger.debug("Validating X509Certificate AuthorityInformationAccess  for CA{}", caName);

        final byte[] octectBytes = x509Certificate.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (octectBytes != null) {
            final Set<String> criticalExtensionOIDs = x509Certificate.getCriticalExtensionOIDs();
            isExtensionCritical(criticalExtensionOIDs, caName);

            final AccessDescription[] accessDescriptors = getAccessDescriptors(octectBytes, caName);
            isValidAccessDescriptors(accessDescriptors, caName);
        }
    }

    private void isExtensionCritical(final Set<String> criticalExtensionOIDs, final String caName) throws InvalidAuthorityInformationAccessExtension {
        if (criticalExtensionOIDs.contains(Extension.authorityInfoAccess.getId())) {
            logger.error("AuthorityInformationAccess " + ErrorMessages.EXTENSION_NON_CRITICAL, " for CA {} ", caName);
            throw new InvalidAuthorityInformationAccessExtension(ErrorMessages.EXTENSION_NON_CRITICAL);
        }
    }

    private AccessDescription[] getAccessDescriptors(final byte[] octectBytes, final String caName) {
        final ASN1Sequence aSN1Sequence = getASN1Sequence(octectBytes, caName);
        final AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(aSN1Sequence);

        return authorityInformationAccess.getAccessDescriptions();
    }

    private ASN1Sequence getASN1Sequence(final byte[] octetBytes, final String caName) throws InvalidAuthorityInformationAccessExtension {
        final ASN1Sequence aSN1Sequence;

        try {
            final byte[] encodedOctectBytes = X509ExtensionUtil.fromExtensionValue(octetBytes).getEncoded();
            aSN1Sequence = ASN1Sequence.getInstance(ASN1Primitive.fromByteArray(encodedOctectBytes));
        } catch (IOException iOException) {
            logger.error(ErrorMessages.IO_EXCEPTION, "for CA {} ", caName, "exception message is {} ", iOException.getMessage());
            throw new InvalidAuthorityInformationAccessExtension(ErrorMessages.IO_EXCEPTION, iOException);
        }

        return aSN1Sequence;
    }

    private void isValidAccessDescriptors(final AccessDescription[] accessDescriptors, final String caName) throws InvalidAuthorityInformationAccessExtension {
        final Set<AccessDescription> iOCSPAccessDescriptions = new HashSet<AccessDescription>();

        for (final AccessDescription accessDescription : accessDescriptors) {
            if (accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_ocsp) || accessDescription.getAccessMethod().equals(X509ObjectIdentifiers.id_ad_caIssuers)) {
                iOCSPAccessDescriptions.add(accessDescription);
            }
        }

        if (iOCSPAccessDescriptions.size() <= 0) {
            logger.error(ErrorMessages.ACCESS_METHOD_VALIDATION_FAILED, "for CA {} ", caName);
            throw new InvalidAuthorityInformationAccessExtension(ErrorMessages.ACCESS_METHOD_VALIDATION_FAILED);
        }
    }
}