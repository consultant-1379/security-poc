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

import org.bouncycastle.asn1.x509.Extension;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidBasicConstraintsExtension;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateGenerationInfoData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateRequestData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CSRExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CertificateExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.rfc.CertificateBase;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

@RunWith(MockitoJUnitRunner.class)
public class BasicConstraintsValidatorTest {
    @InjectMocks
    BasicConstraintsValidator basicConstraintsValidator;

    @Mock
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Mock
    CertificateExtensionUtils certificateExtensionUtils;

    @Mock
    CSRExtensionUtils csrExtensionUtils;

    @Mock
    Logger logger;

    CACertificateValidationInfo caCertificateValidationInfo = new CACertificateValidationInfo();
    CertificateBase certificateBase = new CertificateBase();
    String caName = "caName";
    X509Certificate x509Certificate = null;

    @Test
    public void testValidate() throws CertificateException, FileNotFoundException {
        x509Certificate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");
        caCertificateValidationInfo = setupData(x509Certificate);

        Mockito.when(certificateExtensionUtils.getCertificateAttributeExtensionValue(x509Certificate, Extension.basicConstraints.getId())).thenReturn(x509Certificate.getEncoded());
        Mockito.when(csrExtensionUtils.getCSRAttributeExtensionValue(caName, Extension.basicConstraints)).thenReturn(x509Certificate.getEncoded());

        basicConstraintsValidator.validate(caCertificateValidationInfo);

    }

    @Test(expected = InvalidBasicConstraintsExtension.class)
    public void testInvalidBasicConstraintsExtension() throws CertificateException, FileNotFoundException {
        x509Certificate = certificateBase.getX509Certificate("entity.crt");
        caCertificateValidationInfo = setupData(x509Certificate);

        Mockito.when(certificateExtensionUtils.getCertificateAttributeExtensionValue(x509Certificate, Extension.basicConstraints.getId())).thenReturn(caName.getBytes());
        Mockito.when(csrExtensionUtils.getCSRAttributeExtensionValue(caName, Extension.basicConstraints)).thenReturn(x509Certificate.getEncoded());

        basicConstraintsValidator.validate(caCertificateValidationInfo);
    }

    private CACertificateValidationInfo setupData(final X509Certificate x509Certificate) throws CertificateException, FileNotFoundException {

        caCertificateValidationInfo.setCertificate(x509Certificate);
        caCertificateValidationInfo.setCaName(caName);

        CertificateRequestData certificateRequestData = new CertificateRequestData();
        certificateRequestData.setCsr(x509Certificate.getEncoded());

        CertificateGenerationInfoData certificateGenerationInfoData = new CertificateGenerationInfoData();
        certificateGenerationInfoData.setCertificateRequestData(certificateRequestData);
        return caCertificateValidationInfo;
    }

}
