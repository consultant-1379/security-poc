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

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidBasicConstraintsExtension;

@RunWith(MockitoJUnitRunner.class)
public class X509CertificateBasicConstraintsValidatorTest {
    @InjectMocks
    X509CertificateBasicConstraintsValidator certificateBasicConstraintsValidator;

    @Mock
    BasicConstraints basicConstraints;

    @Mock
    Logger logger;

    @Test
    public void testValidate() throws CertificateException, FileNotFoundException {
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");
        certificateBasicConstraintsValidator.validate(certificateBase.getRootCACertificateInfo(certificateToValidate));
    }

    @Test
    public void testValidate_PathLengthCheck() throws CertificateException, FileNotFoundException {
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("factory.crt");

        Mockito.when(basicConstraints.isCA()).thenReturn(false);
        certificateBasicConstraintsValidator.validate(certificateBase.getRootCACertificateInfo(certificateToValidate));
    }
    @Test(expected = InvalidBasicConstraintsExtension.class)
    public void testValidate_isCA() throws CertificateException, FileNotFoundException {
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("entity.crt");

        Mockito.when(basicConstraints.isCA()).thenReturn(false);
        certificateBasicConstraintsValidator.validate(certificateBase.getRootCACertificateInfo(certificateToValidate));
        Mockito.verify(logger).error("BasicConstraints Validation failed(path length should be greater than zero) ");
    }

}
