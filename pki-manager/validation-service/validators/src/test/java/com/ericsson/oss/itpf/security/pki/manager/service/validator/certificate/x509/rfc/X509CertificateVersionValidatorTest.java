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

import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.UnSupportedCertificateVersion;

@RunWith(MockitoJUnitRunner.class)
public class X509CertificateVersionValidatorTest {

    @InjectMocks
    X509CertificateVersionValidator CertificateVersionValidator;

    @Mock
    Logger logger;

    @Mock
    X509Certificate x509Certificate;

    @Test
    public void validate() throws CertificateException, FileNotFoundException {
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");
        CertificateVersionValidator.validate(certificateBase.getRootCACertificateInfo(certificateToValidate));
    }

    @Test(expected = UnSupportedCertificateVersion.class)
    public void validate_Exception() throws CertificateException, FileNotFoundException {
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = x509Certificate;
        Mockito.when(x509Certificate.getVersion()).thenReturn(2);
        CertificateVersionValidator.validate(certificateBase.getRootCACertificateInfo(certificateToValidate));
        Mockito.verify(logger).error("Invalid Certificate Version");
    }
}
