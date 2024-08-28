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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder;

import java.security.cert.X509Certificate;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.ExtCACertificatePersistanceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;

/**
 * This class updates chain of issuerCertificate relations from external CA certificate till Root CA
 * 
 * @author tcsmanp
 *
 */

public class ExtCAIssuerCertificateChainBuilder {

    @Inject
    ExtCACertificatePersistanceHandler extCACertificatePersistanceHandler;

    @Inject
    Logger logger;

    /**
     * This method updates chain of issuerCertificate relations from external CA certificate till Root CA
     * 
     * @param x509Certificate
     *            The X509 certificate object.
     * @throws CertificateNotFoundException
     *             Thrown when external ca certificate is not found in database.
     * @throws CertificateServiceException
     *             Thrown when certificate encoding fail during external certificate chain build.
     */
    public void updateIssuerCertificateChain(final X509Certificate x509Certificate) throws CertificateNotFoundException, CertificateServiceException {
        logger.debug("Building certificate Chain for external CA certificates");

        extCACertificatePersistanceHandler.updateIssuerCertificateChain(x509Certificate);

        logger.info("Certificate chain build completed successfully for external CA certificates");
    }

}
