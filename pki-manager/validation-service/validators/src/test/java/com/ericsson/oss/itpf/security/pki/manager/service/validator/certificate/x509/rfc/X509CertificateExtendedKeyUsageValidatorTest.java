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
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.x509.Extension;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CertificateExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

@RunWith(MockitoJUnitRunner.class)
public class X509CertificateExtendedKeyUsageValidatorTest {

    @InjectMocks
    X509CertificateExtendedKeyUsageValidator x509CertificateExtendedKeyUsageValidator;

    @Mock
    X509Certificate x509Certificate;

    @Mock
    CertificateExtensionUtils certificateExtensionUtils;

    @Mock
    Logger logger;

    final static String caName = "caName";

    @Test
    public void testValidate() throws CertificateException, FileNotFoundException {
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");
        final byte[] extensionValue = certificateToValidate.getExtensionValue(Extension.extendedKeyUsage.getId());

        Set<String> extensionOIDs = new HashSet<String>();
        extensionOIDs.add("2.5.29.37");
        CACertificateValidationInfo caCertificateValidationInfo = new CACertificateValidationInfo();
        caCertificateValidationInfo.setCaName(caName);
        caCertificateValidationInfo.setCertificate(x509Certificate);
        Mockito.when(x509Certificate.getExtensionValue(Extension.extendedKeyUsage.getId())).thenReturn(extensionValue);
        final byte[] certificateExtensionValue = certificateToValidate.getExtensionValue(Extension.extendedKeyUsage.getId());
        Mockito.when(certificateExtensionUtils.getCertificateAttributeExtensionValue(x509Certificate, Extension.extendedKeyUsage.getId())).thenReturn(certificateExtensionValue);

        Mockito.when(x509Certificate.getCriticalExtensionOIDs()).thenReturn(extensionOIDs);
        x509CertificateExtendedKeyUsageValidator.validate(caCertificateValidationInfo);
    }

}
