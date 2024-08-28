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

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.CertificateExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

@RunWith(MockitoJUnitRunner.class)
public class X509CertificateIssuerUniqueIdentifierValidatorTest {

    @InjectMocks
    X509CertificateIssuerUniqueIdentifierValidator x509CertificateIssuerUniqueIdentifierValidator;

    @Mock
    Logger logger;

    @Mock
    X509Certificate x509Certificate;

    @Test
    public void testValidateTest() throws CertificateException, FileNotFoundException {

        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");
        CACertificateValidationInfo caCertificateValidationInfo = certificateBase.getRootCACertificateInfo(certificateToValidate);

        x509CertificateIssuerUniqueIdentifierValidator.validate(caCertificateValidationInfo);
    }

    @Test(expected = CertificateExtensionException.class)
    public void testValidateTest_CertificateExtensionException() throws CertificateException, FileNotFoundException {
        final String caName = "caName";
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");
        CACertificateValidationInfo caCertificateValidationInfo = certificateBase.getRootCACertificateInfo(x509Certificate);
        Mockito.when(x509Certificate.getVersion()).thenReturn(1);
        Mockito.when(x509Certificate.getIssuerUniqueID()).thenReturn(certificateToValidate.getIssuerUniqueID());
        x509CertificateIssuerUniqueIdentifierValidator.validate(caCertificateValidationInfo);

        Mockito.verify(logger).error(ErrorMessages.ISSUER_UNIQUE_IDENTIFIER_IS_NOT_ALLOWED, " for CA {} ", caName);

    }
}
