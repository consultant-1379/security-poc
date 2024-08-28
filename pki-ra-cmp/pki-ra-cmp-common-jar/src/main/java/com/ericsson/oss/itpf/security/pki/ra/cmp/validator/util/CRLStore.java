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
package com.ericsson.oss.itpf.security.pki.ra.cmp.validator.util;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.cert.*;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.util.constants.Constants;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.validator.exception.CRLValidationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.cdt.CRL;

/**
 * This class is used to get CRL file from the cache.
 * 
 * @author tcsramc
 *
 */
public class CRLStore {

    @Inject
    CRLCacheWrapper cRLCacheWrapper;

    @Inject
    protected Logger logger;

    /**
     * This method is used to fetch the CRL from the loaded cache based on the issuer name provided. if respective cRL is found, then it converts into X509CRL and returns else exception is thrown.
     * 
     * @param issuerName
     *            issuer for which CRL has to be fetched.
     * @return
     * @throws CRLValidationException
     *             This exception will handle certificateException(is thrown if no Provider supports a CertificateFactory implementation for the specified type.) and CRLException(is thrown if any
     *             parsing errors occurs while generating CRL)
     * @throws IOException
     *             is thrown if an I/0 Error occurs while closing ByteArrayInputStream.
     */
    public X509CRL getCRL(final String issuerName) throws CRLValidationException, IOException {

        X509CRL x509cRL = null;
        CertificateFactory certificateFactory;
        byte[] cRLEncoded = null;
        ByteArrayInputStream crlInputStream = null;
        try {
            final CRL cRLModel = cRLCacheWrapper.get(issuerName);
            if (cRLModel != null) {
                cRLEncoded = cRLModel.getCrlEncoded();
                crlInputStream = new ByteArrayInputStream(cRLEncoded);
                certificateFactory = CertificateFactory.getInstance(Constants.X509);
                x509cRL = (X509CRL) certificateFactory.generateCRL(crlInputStream);
            } else {
                logger.warn("CRL File is not found in the cache");
            }
        } catch (CertificateException certificateException) {
            logger.error("Exception since  no Provider supports a CertificateFactorySpi implementation for the specified type");
            throw new CRLValidationException(ErrorMessages.CERTIFICATE_TYPE_NOT_SUPPORTED_BY_THE_PROVIDER, certificateException);

        } catch (CRLException crlException) {
            logger.error("Exception thrown since data in the input stream does not contain an inherent end-of-CRL marker (other than EOF) and there is trailing data after the CRL is parsed, a CRLException is thrown");
            throw new CRLValidationException(ErrorMessages.CRL_FORMAT_ERROR, crlException);

        } finally {
            if (crlInputStream != null) {
                crlInputStream.close();
            }
        }
        return x509cRL;
    }
}
