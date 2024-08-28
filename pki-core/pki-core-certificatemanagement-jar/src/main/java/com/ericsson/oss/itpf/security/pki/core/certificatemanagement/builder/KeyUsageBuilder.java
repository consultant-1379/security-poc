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
import java.util.List;

import javax.inject.Inject;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificateextension.InvalidKeyUsageException;

/**
 * This class build {@link org.bouncycastle.asn1.x509.KeyUsage} extension for the certificate.
 * 
 */
public class KeyUsageBuilder {

    @Inject
    Logger logger;

    /**
     * Builds {@link KeyUsage} from certificate extension passed.
     * 
     * @param certificateExtension
     *            CertificateExtension that to be built as {@link KeyUsage}
     * @return Extension that has {@link KeyUsage} object.
     * @throws InvalidKeyUsageException
     *             Thrown incase if any failures occur in building extension.
     */
    public Extension buildKeyUsage(final CertificateExtension certificateExtension) throws InvalidKeyUsageException {

        final KeyUsage keyUsage = (KeyUsage) certificateExtension;

        logger.debug("Adding KeyUsage extension to certificate extensions {} ", keyUsage);

        int value = 0;
        value = generateKeyUsage(keyUsage.getSupportedKeyUsageTypes());
        try {
            final DEROctetString keyUsageExtension = new DEROctetString(new org.bouncycastle.asn1.x509.KeyUsage(value));
            final Extension extension = new Extension(Extension.keyUsage, keyUsage.isCritical(), keyUsageExtension);
            logger.debug("KeyUsage extension is prepared and will be added to the extension list for the certificate");
            return extension;
        } catch (IOException ioException) {
            logger.error(ErrorMessages.EXTENSION_ENCODING_IS_INVALID, ioException);
            throw new InvalidKeyUsageException(ErrorMessages.EXTENSION_ENCODING_IS_INVALID);
        }
    }

    public int generateKeyUsage(final List<KeyUsageType> keyUsageTypes) throws InvalidKeyUsageException {

        int keyUsage = 0;

        for (final KeyUsageType keyUsageType : keyUsageTypes) {
            keyUsage = keyUsage | getKeyUsage(keyUsageType);
        }
        return keyUsage;
    }

    private int getKeyUsage(final KeyUsageType keyUsageType) throws InvalidKeyUsageException {

        switch (keyUsageType) {
        case DIGITAL_SIGNATURE:
            return org.bouncycastle.asn1.x509.KeyUsage.digitalSignature;
        case NON_REPUDIATION:
            return org.bouncycastle.asn1.x509.KeyUsage.nonRepudiation;
        case KEY_ENCIPHERMENT:
            return org.bouncycastle.asn1.x509.KeyUsage.keyEncipherment;
        case DATA_ENCIPHERMENT:
            return org.bouncycastle.asn1.x509.KeyUsage.dataEncipherment;
        case KEY_AGREEMENT:
            return org.bouncycastle.asn1.x509.KeyUsage.keyAgreement;
        case KEY_CERT_SIGN:
            return org.bouncycastle.asn1.x509.KeyUsage.keyCertSign;
        case CRL_SIGN:
            return org.bouncycastle.asn1.x509.KeyUsage.cRLSign;
        case ENCIPHER_ONLY:
            return org.bouncycastle.asn1.x509.KeyUsage.encipherOnly;
        case DECIPHER_ONLY:
            return org.bouncycastle.asn1.x509.KeyUsage.decipherOnly;
        default:
            throw new InvalidKeyUsageException(ErrorMessages.INVALID_KEYUSAGE_TYPE);
        }
    }

}
