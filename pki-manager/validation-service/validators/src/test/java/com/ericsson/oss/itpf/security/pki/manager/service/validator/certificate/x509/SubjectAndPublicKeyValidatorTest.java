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

import java.io.IOException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.cert.*;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequest;
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.util.CertificateRequestUtility;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateGenerationInfoData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateRequestData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.rfc.CertificateBase;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

@RunWith(PowerMockRunner.class)
@PrepareForTest(CertificateRequestUtility.class)
public class SubjectAndPublicKeyValidatorTest {

    @InjectMocks
    SubjectAndPublicKeyValidator subjectAndPublicKeyValidator;

    @Mock
    CACertificateValidationInfo caCertificateValidationInfo;

    @Mock
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Mock
    X509Certificate x509Certificate;

    @Mock
    CertificateGenerationInfoData certificateGenerationInfoData;

    @Mock
    CertificateRequestData certificateRequestData;

    @Mock
    JcaPKCS10CertificationRequest certificationRequest;

    @Mock
    Logger logger;

    @Test
    public void testValidate() throws CertificateException, InvalidKeyException, NoSuchAlgorithmException, IOException {

        final String caName = "caName";

        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");

        PowerMockito.mockStatic(CertificateRequestUtility.class);

        Mockito.when(caCertificateValidationInfo.getCertificate()).thenReturn(certificateToValidate);
        Mockito.when(caCertificateValidationInfo.getCaName()).thenReturn(caName);
        Mockito.when(caCertificatePersistenceHelper.getLatestCertificateGenerationInfo(caName)).thenReturn(certificateGenerationInfoData);
        Mockito.when(certificateGenerationInfoData.getCertificateRequestData()).thenReturn(certificateRequestData);

        Mockito.when(certificateGenerationInfoData.getCertificateRequestData().getCsr()).thenReturn(certificateToValidate.getEncoded());

        Mockito.when(x509Certificate.getPublicKey()).thenReturn(certificateToValidate.getPublicKey());

        Mockito.when(CertificateRequestUtility.getJCAPKCS10CertificationRequest(certificateGenerationInfoData.getCertificateRequestData().getCsr())).thenReturn(certificationRequest);

        Mockito.when(certificationRequest.getPublicKey()).thenReturn(certificateToValidate.getPublicKey());

        Mockito.when(certificationRequest.getSubject()).thenReturn(new X500Name(certificateToValidate.getSubjectDN().getName()));

        subjectAndPublicKeyValidator.validate(caCertificateValidationInfo);
        Mockito.verify(caCertificatePersistenceHelper, Mockito.times(2)).getLatestCertificateGenerationInfo(caName);
    }

    @Test(expected = InvalidSubjectException.class)
    public void testValidate_IOException() throws CertificateException, InvalidKeyException, NoSuchAlgorithmException, IOException {

        final String caName = "caName";

        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");

        PowerMockito.mockStatic(CertificateRequestUtility.class);

        Mockito.when(caCertificateValidationInfo.getCertificate()).thenReturn(certificateToValidate);
        Mockito.when(caCertificateValidationInfo.getCaName()).thenReturn(caName);
        Mockito.when(caCertificatePersistenceHelper.getLatestCertificateGenerationInfo(caName)).thenThrow(IOException.class);
        Mockito.when(certificateGenerationInfoData.getCertificateRequestData()).thenReturn(certificateRequestData);

        Mockito.when(certificateGenerationInfoData.getCertificateRequestData().getCsr()).thenReturn(certificateToValidate.getEncoded());

        Mockito.when(x509Certificate.getPublicKey()).thenReturn(certificateToValidate.getPublicKey());

        Mockito.when(CertificateRequestUtility.getJCAPKCS10CertificationRequest(certificateGenerationInfoData.getCertificateRequestData().getCsr())).thenReturn(certificationRequest);

        Mockito.when(certificationRequest.getPublicKey()).thenReturn(certificateToValidate.getPublicKey());

        Mockito.when(certificationRequest.getSubject()).thenReturn(new X500Name(certificateToValidate.getSubjectDN().getName()));

        try {
            subjectAndPublicKeyValidator.validate(caCertificateValidationInfo);
        } catch (Exception e) {
            throw new InvalidSubjectException();
        }
        Mockito.verify(caCertificatePersistenceHelper, Mockito.times(2)).getLatestCertificateGenerationInfo(caName);
    }

    @Test(expected = InvalidSubjectException.class)
    public void testValidateInvalidKeyException() throws CertificateException, InvalidKeyException, NoSuchAlgorithmException, IOException {

        setuData();
        final String caName = "caName";

        Mockito.when(certificationRequest.getSubject()).thenThrow(CertificateEncodingException.class);

        subjectAndPublicKeyValidator.validate(caCertificateValidationInfo);
        Mockito.verify(caCertificatePersistenceHelper).getLatestCertificateGenerationInfo(caName);
    }

    @Test(expected = InvalidSubjectException.class)
    public void testValidateCertificateEncodingException() throws CertificateException, InvalidKeyException, NoSuchAlgorithmException, IOException {

        setuData();
        final String caName = "caName";

        Mockito.when(certificationRequest.getSubject()).thenThrow(CertificateEncodingException.class);

        subjectAndPublicKeyValidator.validate(caCertificateValidationInfo);
        Mockito.verify(caCertificatePersistenceHelper).getLatestCertificateGenerationInfo(caName);
    }

    @Ignore
    @Test(expected = InvalidSubjectException.class)
    public void testValidatecertificateGenerationInfoDataNull() throws CertificateException, InvalidKeyException, NoSuchAlgorithmException, IOException {

        setuData();
        CertificateBase certificateBase = new CertificateBase();
        final String caName = "caName";
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");

        PowerMockito.mockStatic(CertificateRequestUtility.class);
        // Mockito.when(caCertificatePersistenceHelper.getLatestCertificateGenerationInfo(caName)).thenReturn(certificateGenerationInfoData);

        Mockito.when(certificateGenerationInfoData.getCertificateRequestData()).thenReturn(certificateRequestData);

        Mockito.when(certificateGenerationInfoData.getCertificateRequestData().getCsr()).thenReturn(certificateToValidate.getEncoded());

        Mockito.when(CertificateRequestUtility.getJCAPKCS10CertificationRequest(certificateGenerationInfoData.getCertificateRequestData().getCsr())).thenReturn(certificationRequest);

        Mockito.when(caCertificatePersistenceHelper.getLatestCertificateGenerationInfo(caName)).thenReturn(null);

        subjectAndPublicKeyValidator.validate(caCertificateValidationInfo);

        Mockito.verify(caCertificatePersistenceHelper).getLatestCertificateGenerationInfo(caName);

    }

    public void setuData() throws CertificateException, InvalidKeyException, NoSuchAlgorithmException, IOException {

        final String caName = "caName";

        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");

        PowerMockito.mockStatic(CertificateRequestUtility.class);

        Mockito.when(caCertificateValidationInfo.getCertificate()).thenReturn(certificateToValidate);
        Mockito.when(caCertificateValidationInfo.getCaName()).thenReturn(caName);
        Mockito.when(caCertificatePersistenceHelper.getLatestCertificateGenerationInfo(caName)).thenReturn(certificateGenerationInfoData);
        Mockito.when(certificateGenerationInfoData.getCertificateRequestData()).thenReturn(certificateRequestData);

        Mockito.when(certificateGenerationInfoData.getCertificateRequestData().getCsr()).thenReturn(certificateToValidate.getEncoded());

        Mockito.when(x509Certificate.getPublicKey()).thenReturn(certificateToValidate.getPublicKey());

        Mockito.when(CertificateRequestUtility.getJCAPKCS10CertificationRequest(certificateGenerationInfoData.getCertificateRequestData().getCsr())).thenReturn(certificationRequest);

        Mockito.when(certificationRequest.getPublicKey()).thenReturn(certificateToValidate.getPublicKey());

    }

}
