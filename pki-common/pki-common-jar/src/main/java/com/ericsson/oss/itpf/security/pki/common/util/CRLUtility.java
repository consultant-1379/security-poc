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
package com.ericsson.oss.itpf.security.pki.common.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.*;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.x500.RDN;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x500.style.IETFUtils;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.util.constants.Constants;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CRLConversionException;
import com.ericsson.oss.itpf.security.pki.common.util.exception.CertificateUtilityException;

/**
 * This class converts the CRL byte array to X509 CRL
 * 
 * @author xjagcho
 *
 */
public class CRLUtility {
    private CRLUtility() {

    }

    private static final Logger LOGGER = LoggerFactory.getLogger(CRLUtility.class);

    /**
     * This method converts the requested CRL byte array to X509 CRL
     * 
     * @param crlContent
     *            CRL byte array as encoded format
     * 
     * @return X509CRL converted CRL byte array to X509CRL
     * 
     * @throws CRLConversionException
     *             throws when CRL byte array converted to x509CRL
     * 
     */
    public static X509CRL getX509CRL(final byte[] crlContent) throws CRLConversionException {
        LOGGER.debug("getX509CRL method in CRLUtility class");

        X509CRL x509CRL = null;
        ByteArrayInputStream byeArrayInputStream = null;
        try {
            byeArrayInputStream = new ByteArrayInputStream(crlContent);
            x509CRL = (X509CRL) CertificateFactory.getInstance(Constants.X509).generateCRL(byeArrayInputStream);
        } catch (CRLException | CertificateException exception) {
            LOGGER.error(ErrorMessages.CRL_CONVERSION_FAILED);
            throw new CRLConversionException(ErrorMessages.CRL_CONVERSION_FAILED, exception);
        } finally {
            try {
                if (byeArrayInputStream != null) {
                    byeArrayInputStream.close();
                }
            } catch (IOException exception) {
                LOGGER.debug("Exception occured while closing the input stream in CRLUtility class ", exception);
                LOGGER.warn("Exception occured while closing the input stream in CRLUtility class");
            }
        }
        LOGGER.debug("End of getX509CRL method in CRLUtility class");

        return x509CRL;
    }

    /**
     * This method is used to get the issuerName based on X509 CRL
     * 
     * @param x509CRL
     *            CRL as x509CRL
     * @return issuerName IssuerName extracted from the CRL
     * @throws CertificateUtilityException
     *             throws when certificate is invalid
     */
    public String getIssuerCN(final X509CRL x509CRL) throws CertificateUtilityException {
        LOGGER.debug("getIssuerCN method in CRLUtility class");
        String issuerName;
        final X500Principal principal = x509CRL.getIssuerX500Principal();
        final X500Name x500name = new X500Name(principal.getName());
        final RDN commonName = x500name.getRDNs(BCStyle.CN)[0];
        issuerName = IETFUtils.valueToString(commonName.getFirst().getValue());
        LOGGER.debug("End of getIssuerCN method in CRLUtility class");
        return issuerName;

    }
}
