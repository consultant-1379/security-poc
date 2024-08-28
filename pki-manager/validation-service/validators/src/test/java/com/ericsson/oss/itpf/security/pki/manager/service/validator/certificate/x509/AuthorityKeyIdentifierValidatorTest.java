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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509;

import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PowerMockIgnore;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidAuthorityKeyIdentifierExtension;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.rfc.CertificateBase;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

@RunWith(MockitoJUnitRunner.class)
@PrepareForTest(CertificateUtility.class)
@PowerMockIgnore("javax.security.*")
public class AuthorityKeyIdentifierValidatorTest {

    @InjectMocks
    AuthorityKeyIdentifierValidator authorityKeyIdentifierValidator;

    @Mock
    CACertificateValidationInfo caCertificateValidationInfo;

    @Mock
    X509Certificate x509Certificate;

    @Mock
    X509Certificate importCertificate;

    @Mock
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Mock
    CertificateData certificateData;

    @Mock
    Logger logger;

    public static String caName = "caName";

    @Ignore
    @Test(expected = InvalidAuthorityKeyIdentifierExtension.class)
    public void testValidateInvalidAuthorityKeyIdentifierExtension() throws CertificateException, FileNotFoundException {
        PowerMockito.mockStatic(CertificateUtility.class);
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");

        Mockito.when(caCertificateValidationInfo.getCertificate()).thenReturn(certificateToValidate);
        Mockito.when(caCertificateValidationInfo.getCaName()).thenReturn(caName);

        Mockito.when(CertificateUtility.getCertificateFromByteArray(certificateData.getCertificate())).thenReturn(x509Certificate);

        authorityKeyIdentifierValidator.validate(caCertificateValidationInfo);

        Mockito.verify(logger).error(ErrorMessages.CERTIFICATE_ENCODING_FAILED, " for CA {} ", caName, Matchers.anyObject());

    }

    @Ignore
    @Test(expected = CertificateNotFoundException.class)
    public void testValidateCertificateDataNull() throws CertificateException, FileNotFoundException {

        byte[] cert = new byte[] { 1 };

        PowerMockito.mockStatic(CertificateUtility.class);
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");

        Mockito.when(caCertificateValidationInfo.getCertificate()).thenReturn(certificateToValidate);

        Mockito.when(certificateData.getCertificate()).thenReturn(cert);
        Mockito.when(CertificateUtility.getCertificateFromByteArray(certificateData.getCertificate())).thenReturn(x509Certificate);

        authorityKeyIdentifierValidator.validate(caCertificateValidationInfo);

        Mockito.verify(logger).error(ErrorMessages.CSR_NOT_FOUND, " for CA {} ", caName);

    }

}
