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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.rfc;

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.*;

import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

public class CertificateBase {
    public X509Certificate getX509Certificate(final String fileName) throws CertificateException, FileNotFoundException {
        CertificateFactory certificateFactory;
        X509Certificate vendorCert;
        FileInputStream fileInputStream;
        String vendorCertPath = null;
        vendorCertPath = CertificateBase.class.getResource("/Certificates/" + fileName).getPath();
        certificateFactory = CertificateFactory.getInstance("X.509");
        fileInputStream = new FileInputStream(vendorCertPath);
        vendorCert = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
        return vendorCert;
    }

    public CACertificateValidationInfo getRootCACertificateInfo(final X509Certificate certificateToValidate) {
        CACertificateValidationInfo rootCACertificateInfo = new CACertificateValidationInfo();
        rootCACertificateInfo.setCaName("RootCA");
        rootCACertificateInfo.setCertificate(certificateToValidate);
        return rootCACertificateInfo;
    }
}
