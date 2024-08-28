/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl;

import static org.junit.Assert.*
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate
import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate
import org.junit.Test

/**
 * This class prepares certificate required to initate the SecurityGatewayManagementGenerateHandler
 *
 *@author zvetsni
 */

class TestSetupInitializer {
    final Certificate certificate = new Certificate()
    public Certificate getSecGwCert(final String certFile){
        final URL url = Thread.currentThread().getContextClassLoader().getResource(certFile)
        final String certFileName = url.getFile()
        certFileName = URLDecoder.decode(certFileName)
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509")
        final FileInputStream fileInputStream = new FileInputStream(certFileName)
        final X509Certificate x509Certificate = (X509Certificate) certificateFactory.generateCertificate(fileInputStream)
        certificate.setX509Certificate(x509Certificate)
        return certificate
    }
}