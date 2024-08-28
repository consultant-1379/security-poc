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
package com.ericsson.oss.itpf.security.pki.common.util;

import java.io.IOException;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.Extensions;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateParseException;

/**
 * Util class which does CSR related operations.
 * 
 */
public class CertificateRequestUtility {

    private CertificateRequestUtility() {

    }

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateRequestUtility.class);

    /**
     * This method is used to get {@link PKCS10CertificationRequestHolder} object from the byte array.
     * 
     * @param csr
     *            encoded form of csr for which PKCS10CertificateRequestHolder object has to be created.
     * @return {@link PKCS10CertificationRequestHolder} object
     * @throws IOException
     *             Thrown if any I/O Error occurs while conversion.
     */
    public static PKCS10CertificationRequestHolder getCertificateRequestHolder(final byte[] csr) throws IOException {
        final JcaPKCS10CertificationRequest certificationRequest = getJCAPKCS10CertificationRequest(csr);
        return new PKCS10CertificationRequestHolder(certificationRequest);
    }

    /**
     * This method is used to get {@link JcaPKCS10CertificationRequest} object from the byte array.
     * 
     * @param csr
     *            encoded form of csr for which PKCS10CertificateRequestHolder object has to be created.
     * @return {@link JcaPKCS10CertificationRequest} object
     * @throws IOException
     *             Thrown if any I/O Error occurs while conversion.
     */
    public static JcaPKCS10CertificationRequest getJCAPKCS10CertificationRequest(final byte[] csr) throws IOException {

        LOGGER.debug("Creating JcaPKCS10CertificationRequest object from byte array. ");

        final PKCS10CertificationRequest certificationRequest = getPKCS10CertificationRequest(csr);

        final JcaPKCS10CertificationRequest jcaPKCS10CertificationRequest = new JcaPKCS10CertificationRequest(certificationRequest);

        LOGGER.debug("Creating JcaPKCS10CertificationRequest object from byte array done. ");

        return jcaPKCS10CertificationRequest;
    }

    private static PKCS10CertificationRequest getPKCS10CertificationRequest(final byte[] csr) throws IOException {

        LOGGER.debug("Creating PKCS10CertificationRequest object from byte array. ");

        final PKCS10CertificationRequest certificationRequest = new PKCS10CertificationRequest(csr);

        LOGGER.debug("Creating PKCS10CertificationRequest object from byte array done. ");

        return certificationRequest;

    }

    /**
     * This method returns Extension Value from CSR of provided attribute.
     *
     * @param csr
     *            encoded form of a CSR.
     * @param csrAttribute
     *            CSR Attribute can be any of subjectAlternativeName, keyUsage, extendedKeyUsage, basicConstraints, subjectKeyIdentifier , authorityInfoAccess and cRLDistributionPoints.
     * @return extension Value of specific CSR Attribute.
     *
     * @throws CertificateParseException
     *             is thrown if any certificate request parsing errors.
     */
    public static byte[] getAttributeExtensionValue(final byte[] csr, final ASN1ObjectIdentifier csrAttribute) throws CertificateParseException {

        LOGGER.debug("Getting ExtensionValue from Certification Request for Attribute {}", csrAttribute);

        Extensions certificateRequestExtensions = null;
        byte[] certificateRequestExtensionValue = null;
        ASN1Set attributeValues = null;
        JcaPKCS10CertificationRequest certificationRequest = null;

        try {
            certificationRequest = getJCAPKCS10CertificationRequest(csr);
        } catch (IOException ioException) {
            LOGGER.error(ErrorMessages.CSR_ENCODING_FAILED, ioException.getMessage());
            throw new CertificateParseException(ErrorMessages.CSR_ENCODING_FAILED, ioException);
        }

        final Attribute[] csrAttributes = certificationRequest.getAttributes(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest);

        if (csrAttributes.length == 0) {
            LOGGER.error(ErrorMessages.CSR_EXTENSIONS_ERROR);
            throw new CertificateParseException(ErrorMessages.CSR_EXTENSIONS_ERROR);
        }

        attributeValues = csrAttributes[0].getAttrValues();
        if (attributeValues.size() == 0) {
            return null;
        }

        certificateRequestExtensions = Extensions.getInstance(attributeValues.getObjectAt(0));
        if (certificateRequestExtensions != null) {
            final Extension certificateRequestExtension = certificateRequestExtensions.getExtension(csrAttribute);
            if (certificateRequestExtension != null) {
                final DEROctetString certificateRequestOctetString = new DEROctetString(certificateRequestExtension.getExtnValue().getOctets());

                try {
                    certificateRequestExtensionValue = certificateRequestOctetString.getEncoded();
                } catch (IOException ioException) {
                    LOGGER.error(ErrorMessages.CSR_ENCODING_FAILED, ioException.getMessage());
                    throw new CertificateParseException(ErrorMessages.CSR_ENCODING_FAILED, ioException);
                }
            }
        }

        LOGGER.debug("Getting ExtensionValue from Certification Request done for Attribute {}", csrAttribute);
        return certificateRequestExtensionValue;
    }
}
