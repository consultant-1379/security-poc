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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.common.data;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.CRLException;
import java.security.cert.CertificateException;
import java.security.cert.CertificateFactory;
import java.security.cert.X509CRL;
import java.util.Date;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.X509CRLHolder;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;

/**
 * Base class for common functionality.
 * 
 */
public class SetUPData {

    public static final String ROOT_CA_NAME = "ENMRootCA";
    public static final String SUB_CA_NAME = "ENMSubCA";
    public static final String ENTITY_NAME = "Entity";
    public static final String SIGNATURE_ALGORITHM = "SHA1WITHRSA";
    public static final String KEY_GEN_ALGORITHM = "RSA";
    public static final String CERTIFICATE_TYPE = "X.509";

    /**
     * Generates CRL model from the crl file.
     * 
     * @param filename
     *            name of the crl file.
     * @return CRL model formed from the file.
     * @throws IOException
     * @throws CertificateException
     */
    public ExternalCRLInfo getExternalCRLInfo(final String filename) throws IOException, CertificateException {
        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(filename);
        final CertificateFactory certificateFactory = CertificateFactory.getInstance(CERTIFICATE_TYPE);
        try {
            final X509CRL x509CRL = (X509CRL) certificateFactory.generateCRL(inputStream);
            return fillCRL(x509CRL);
        } catch (final CRLException e) {
            e.printStackTrace();
        }
        return null;
    }

    /**
     * @param x509CRL
     * @return
     * @throws IOException
     * @throws CRLException
     */
    private ExternalCRLInfo fillCRL(final X509CRL x509CRL) throws CRLException, IOException {
        final ExternalCRLInfo crl = new ExternalCRLInfo();
        crl.setAutoUpdate(true);
        crl.setAutoUpdateCheckTimer(7);
        crl.setNextUpdate(new Date());
        crl.setUpdateURL("updateURL");
        crl.setX509CRL(new X509CRLHolder(x509CRL.getEncoded()));
        return crl;
    }
}
