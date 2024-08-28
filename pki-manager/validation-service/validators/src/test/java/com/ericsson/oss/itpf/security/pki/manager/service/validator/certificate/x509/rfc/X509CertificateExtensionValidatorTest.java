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

import org.bouncycastle.asn1.x509.Extensions;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

@RunWith(MockitoJUnitRunner.class)
public class X509CertificateExtensionValidatorTest {

    @InjectMocks
    X509CertificateExtensionValidator x509CertificateExtensionValidator;

    @Mock
    X509Certificate x509Certificate;

    @Mock
    Logger logger;

    @Mock
    CACertificateValidationInfo caCertificateValidationInfo;

    @Mock
    Extensions extensions;

    static final String caName = "caName";

    @Test
    public void testValidate() throws CertificateException, FileNotFoundException {

        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");

        Mockito.when(caCertificateValidationInfo.getCertificate()).thenReturn(certificateToValidate);
        Mockito.when(caCertificateValidationInfo.getCaName()).thenReturn(caName);
        x509CertificateExtensionValidator.validate(caCertificateValidationInfo);

        Mockito.verify(logger).debug("Validating X509Certificate CertificateExtension for CA {} ", caName);
    }

}
