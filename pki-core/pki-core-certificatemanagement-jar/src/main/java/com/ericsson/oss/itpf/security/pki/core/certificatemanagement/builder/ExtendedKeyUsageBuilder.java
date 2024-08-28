/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.builder;

import java.io.IOException;
import java.lang.reflect.Field;
import java.util.List;

import javax.inject.Inject;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ExtendedKeyUsage;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificateextension.InvalidExtendedKeyUsageException;

/**
 * This class builds {@link org.bouncycastle.asn1.x509.ExtendedKeyUsage} extension for the certificate.
 * 
 */
public class ExtendedKeyUsageBuilder {

    @Inject
    Logger logger;

    /**
     * Builds {@link ExtendedKeyUsage} from certificate extension passed.
     * 
     * @param certificateExtension
     *            CertificateExtension that to be built as {@link ExtendedKeyUsage}
     * @return Extension that has {@link ExtendedKeyUsage} object.
     * @throws InvalidExtendedKeyUsageException
     *             Thrown incase if any failures occur in building extension.
     */
    public Extension buildExtendedKeyUsage(final CertificateExtension certificateExtension) throws InvalidExtendedKeyUsageException {

        final ExtendedKeyUsage extendedKeyUsage = (ExtendedKeyUsage) certificateExtension;

        logger.debug("Adding ExtendedKeyUsage extension to certificate extensions {} ", extendedKeyUsage);
        try {
            Extension extension = null;
            if (!extendedKeyUsage.getSupportedKeyPurposeIds().isEmpty()) {

                final DEROctetString extendedKeyUsageExtension = new DEROctetString(getExtendedKeyUsage(extendedKeyUsage.getSupportedKeyPurposeIds()));

                extension = new Extension(Extension.extendedKeyUsage, extendedKeyUsage.isCritical(), extendedKeyUsageExtension);
            }
            return extension;
        } catch (IOException ioException) {
            logger.error(ErrorMessages.EXTENSION_ENCODING_IS_INVALID, ioException);
            throw new InvalidExtendedKeyUsageException(ErrorMessages.EXTENSION_ENCODING_IS_INVALID);
        }
    }

    /**
     * @param keyPurposeData
     * @return
     * @throws InvalidExtendedKeyUsageException
     *             thrown when ExtendedKeyUsage in certificate extensions is not valid.
     */
    public org.bouncycastle.asn1.x509.ExtendedKeyUsage getExtendedKeyUsage(final List<com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.KeyPurposeId> keyPurposeData)
            throws InvalidExtendedKeyUsageException {

        try {
            org.bouncycastle.asn1.x509.KeyPurposeId[] keyPurposeIds1 = new org.bouncycastle.asn1.x509.KeyPurposeId[keyPurposeData.size()];
            for (int i = 0; i < keyPurposeData.size(); i++) {
                Field field;
                field = org.bouncycastle.asn1.x509.KeyPurposeId.class.getDeclaredField(keyPurposeData.get(i).getValue());

                keyPurposeIds1[i] = (org.bouncycastle.asn1.x509.KeyPurposeId) field.get(null);

            }
            return new org.bouncycastle.asn1.x509.ExtendedKeyUsage(keyPurposeIds1);
        } catch (IllegalAccessException illegalAccessException) {
            logger.error(ErrorMessages.ERROR_BUILDING_EXTENDED_KEY_USAGE_EXTENSION, illegalAccessException);
            throw new InvalidExtendedKeyUsageException(ErrorMessages.ERROR_BUILDING_EXTENDED_KEY_USAGE_EXTENSION);
        } catch (NoSuchFieldException noSuchFieldException) {
            logger.error(ErrorMessages.ERROR_BUILDING_EXTENDED_KEY_USAGE_EXTENSION, noSuchFieldException);
            throw new InvalidExtendedKeyUsageException(ErrorMessages.ERROR_BUILDING_EXTENDED_KEY_USAGE_EXTENSION);
        }
    }
}
