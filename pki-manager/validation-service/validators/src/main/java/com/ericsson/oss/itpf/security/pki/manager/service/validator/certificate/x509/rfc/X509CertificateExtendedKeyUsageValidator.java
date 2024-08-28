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
import java.security.cert.X509Certificate;

import javax.inject.Inject;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidExtendedKeyUsageExtension;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CertificateExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

/**
 * This class is used to validate CertificateExtendedKeyUsage for the imported certificate.
 * 
 * @author tcsramc
 *
 */
public class X509CertificateExtendedKeyUsageValidator implements CommonValidator<CACertificateValidationInfo> {

    @Inject
    Logger logger;

    @Inject
    CertificateExtensionUtils certificateExtensionUtils;

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CACertificateValidationInfo cACertificateValidationInfo) throws ValidationException {
        validateExtendedKeyUsage(cACertificateValidationInfo.getCaName(), cACertificateValidationInfo.getCertificate());
    }

    public void validateExtendedKeyUsage(final String caName, final X509Certificate x509Certificate) throws InvalidExtendedKeyUsageExtension {

        final byte[] extensionValue = x509Certificate.getExtensionValue(Extension.extendedKeyUsage.getId());
        if (extensionValue != null) {
            logger.debug("Validating X509Certificate Extended keyUSage for CA {} ", caName, "ExtensionValue is {}", extensionValue);
            try {
                ASN1InputStream localASN1InputStream = new ASN1InputStream(new ByteArrayInputStream(extensionValue));

                localASN1InputStream = new ASN1InputStream(new ByteArrayInputStream(((ASN1OctetString) localASN1InputStream.readObject()).getOctets()));

                final ExtendedKeyUsage localExtendedKeyUsage = ExtendedKeyUsage.getInstance(localASN1InputStream.readObject());

                if (localExtendedKeyUsage == null) {
                    logger.error(ErrorMessages.EXTENDED_KEY_USAGE_IS_NULL_INVALID, "for CA {} ", caName);
                    throw new InvalidExtendedKeyUsageExtension(ErrorMessages.EXTENDED_KEY_USAGE_IS_NULL_INVALID + " for CA " + caName);
                }
            } catch (IOException iOException) {
                logger.error(ErrorMessages.IO_EXCEPTION, "for CA {} while validating for Extended Key Usage", caName, iOException.getMessage());
                throw new InvalidExtendedKeyUsageExtension(ErrorMessages.IO_EXCEPTION+ " for CA " + caName + " while validating for Extended Key Usage", iOException);
            }
        }
    }

}
