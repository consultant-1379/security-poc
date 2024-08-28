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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.common.utils;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidBasicConstraintsExtension;

/**
 * This class is a util class for X509Certificate
 * 
 * @author tcsramc
 *
 */
public class X509CertificateUtility {
    private X509CertificateUtility() {

    }

    private static final Logger LOGGER = LoggerFactory.getLogger(X509CertificateUtility.class);

    /**
     * This method is used to getBasicConstraints from x509Certificate.
     * 
     * @param x509Certificate
     *            from which basic constraints has to be fetched
     * @return
     * @throws InvalidBasicConstraintsExtension
     *             is thrown if any error occurs while fetching basic constraints from x509certificate.
     */
    public static BasicConstraints getBasicConstraints(final X509Certificate x509Certificate) throws InvalidBasicConstraintsExtension {
        BasicConstraints basicConstraints;

        try {
            final byte[] extensionValue = x509Certificate.getExtensionValue(Extension.basicConstraints.getId());
            final DEROctetString derOctetString = (DEROctetString) new ASN1InputStream(new ByteArrayInputStream(extensionValue)).readObject();

            basicConstraints = BasicConstraints.getInstance(ASN1Sequence.getInstance(derOctetString.getOctets()));
            if (basicConstraints == null) {
                LOGGER.error(ErrorMessages.BASIC_CONSTRAINTS_NULL);
                throw new InvalidBasicConstraintsExtension(ErrorMessages.BASIC_CONSTRAINTS_NULL);
            }
        } catch (IOException iOException) {
            LOGGER.error(ErrorMessages.IO_EXCEPTION, iOException.getMessage());
            throw new InvalidBasicConstraintsExtension(ErrorMessages.IO_EXCEPTION, iOException);
        }
        return basicConstraints;
    }
}
