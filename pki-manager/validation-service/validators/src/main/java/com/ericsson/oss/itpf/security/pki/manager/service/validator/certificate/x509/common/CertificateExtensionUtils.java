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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.List;

import javax.inject.Inject;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;

/**
 * This class is used as utility class to get byte arrays based on extension values.
 *
 * @author tcsnavg
 *
 */
public class CertificateExtensionUtils {

    @Inject
    Logger logger;

    @Inject
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    /**
     * This method is used to extract the extension value from x509Certificate for the given attributeId.
     * 
     * @param x509Certificate
     *            from which extension value has to be fetched.
     * @param attributeId
     *            for which extension value has to be fetched.
     * @return extension value in byte array
     * @throws MissingMandatoryFieldException
     *             is thrown if particular extension is not present in the x509certificate.
     */
    public byte[] getCertificateAttributeExtensionValue(final X509Certificate x509Certificate, final String attributeId) throws MissingMandatoryFieldException {

        final byte[] certificateExtensionValue = x509Certificate.getExtensionValue(attributeId);

        if (certificateExtensionValue == null) {
            logger.error(ErrorMessages.EXTENSION_IS_NULL, "{} for attributeID  {} ", attributeId);
            throw new MissingMandatoryFieldException(ErrorMessages.EXTENSION_IS_NULL);
        }

        return certificateExtensionValue;
    }

    /**
     * This method is used to compare CSR fields against Certificate fields
     * 
     * @param csrIDs
     *            csrFields to compare against Certificate
     * @param certificateIDs
     *            certificate fields against which csr fields has to be compared.
     * @return true if csr and certificate fields are matching, false if both are mismatching
     */
    public boolean compareCSRandCertificateFields(final List<?> csrIDs, final List<?> certificateIDs) {
        boolean isIdPresent = true;
        for (final Object csrId : csrIDs) {
            if (!(certificateIDs.contains(csrId))) {
                isIdPresent = false;
                break;
            }
        }
        return isIdPresent;
    }

    /**
     * This method is used to get keypurposeIds from the given extension.
     * 
     * @param extensionValue
     *            from which keypurposeIds has to be fetched.
     * @return keypurposeIds
     * @throws IOException
     *             if any I/O error occurs while reading objects.
     */
    public KeyPurposeId[] getKeyPurposeID(final byte[] extensionValue) throws IOException {
        final KeyPurposeId[] keyPurposeIDs;
        ASN1InputStream localASN1InputStream = new ASN1InputStream(new ByteArrayInputStream(extensionValue));

        localASN1InputStream = new ASN1InputStream(new ByteArrayInputStream(((ASN1OctetString) localASN1InputStream.readObject()).getOctets()));

        final ExtendedKeyUsage localExtendedKeyUsage = ExtendedKeyUsage.getInstance(localASN1InputStream.readObject());

        keyPurposeIDs = localExtendedKeyUsage.getUsages();

        return keyPurposeIDs;
    }

}
