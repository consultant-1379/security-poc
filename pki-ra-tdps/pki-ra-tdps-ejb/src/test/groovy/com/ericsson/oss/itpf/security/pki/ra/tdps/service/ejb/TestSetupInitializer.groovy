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
package com.ericsson.oss.itpf.security.pki.ra.tdps.service.ejb;

import java.security.cert.CertificateFactory
import java.security.cert.X509Certificate

/**
 * This class is responsible to prepare the certificate data.
 *
 *  @author zkakven
 *  
 */

public class TestSetupInitializer {

    public static byte[] getTDPSCert(final String filePath) {
        X509Certificate tDPSCert = null
        FileInputStream fileInputStream
        String tDPSCertPath = null
        tDPSCertPath = TDPSBeanTest.class.getResource(filePath).getPath()
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509")
        fileInputStream = new FileInputStream(tDPSCertPath)
        tDPSCert = (X509Certificate) certificateFactory.generateCertificate(fileInputStream)
        return tDPSCert.getEncoded()
    }
}
