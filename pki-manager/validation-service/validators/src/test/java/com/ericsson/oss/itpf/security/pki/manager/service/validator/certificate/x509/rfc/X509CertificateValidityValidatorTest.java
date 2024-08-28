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
import java.security.cert.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.ExpiredCertificateException;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

@RunWith(MockitoJUnitRunner.class)
public class X509CertificateValidityValidatorTest {

    @InjectMocks
    X509CertificateValidityValidator x509CertificateValidityValidator;

    @Mock
    CACertificateValidationInfo caCertificateValidationInfo;

    @Mock
    X509Certificate x509Certificate;

    @Mock
    Logger logger;

    @Test
    public void testValidate() throws CertificateException, FileNotFoundException {
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10018.cer");

        Mockito.when(caCertificateValidationInfo.getCertificate()).thenReturn(certificateToValidate);

        x509CertificateValidityValidator.validate(caCertificateValidationInfo);

        Mockito.verify(caCertificateValidationInfo).getCertificate();

    }

    @Test(expected = ExpiredCertificateException.class)
    public void testValidateValidationException() throws CertificateException, FileNotFoundException {

        Mockito.when(caCertificateValidationInfo.getCertificate()).thenReturn(x509Certificate);

        Mockito.doThrow(CertificateNotYetValidException.class).when(x509Certificate).checkValidity();
        x509CertificateValidityValidator.validate(caCertificateValidationInfo);

        Mockito.verify(caCertificateValidationInfo).getCertificate();

    }

}
