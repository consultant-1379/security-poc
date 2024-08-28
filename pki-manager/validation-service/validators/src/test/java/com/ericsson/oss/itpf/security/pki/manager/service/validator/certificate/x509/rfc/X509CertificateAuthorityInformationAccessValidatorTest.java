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
import java.io.IOException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.x509.AuthorityInformationAccess;
import org.bouncycastle.asn1.x509.Extension;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidAuthorityInformationAccessExtension;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CertificateExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

@RunWith(MockitoJUnitRunner.class)
public class X509CertificateAuthorityInformationAccessValidatorTest {

    @InjectMocks
    X509CertificateAuthorityInformationAccessValidator x509CertificateAuthorityInformationAccessValidator;

    @Mock
    Logger logger;

    @Mock
    CACertificateValidationInfo caCertificateValidationInfo;

    @Mock
    X509Certificate x509Certificate;

    @Mock
    CertificateExtensionUtils certificateExtensionUtils;

    @Mock
    AuthorityInformationAccess authorityInformationAccess;

    static final String caName = "caName";

    @Test
    public void testValidate() throws CertificateException, IOException {
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");

        final Set<String> criticalExtensionOIDs = new HashSet<String>();
        criticalExtensionOIDs.add("2.5.29.35");

        Mockito.when(caCertificateValidationInfo.getCertificate()).thenReturn(certificateToValidate);
        Mockito.when(caCertificateValidationInfo.getCaName()).thenReturn(caName);

        Mockito.when(x509Certificate.getCriticalExtensionOIDs()).thenReturn(criticalExtensionOIDs);
        final byte[] extensionValue = certificateToValidate.getExtensionValue(Extension.authorityInfoAccess.getId());
        Mockito.when(certificateExtensionUtils.getCertificateAttributeExtensionValue(certificateToValidate, Extension.authorityInfoAccess.getId())).thenReturn(extensionValue);

        x509CertificateAuthorityInformationAccessValidator.validate(caCertificateValidationInfo);

    }

    @Test(expected = InvalidAuthorityInformationAccessExtension.class)
    public void testValidate_AccessException() throws CertificateException, FileNotFoundException {
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");

        Mockito.when(caCertificateValidationInfo.getCertificate()).thenReturn(x509Certificate);
        Mockito.when(caCertificateValidationInfo.getCaName()).thenReturn(caName);
        Set<String> criticalExtensionOIDs = new HashSet<String>();
        criticalExtensionOIDs.add("1.3.6.1.5.5.7.1.1");
        Mockito.when(x509Certificate.getCriticalExtensionOIDs()).thenReturn(criticalExtensionOIDs);
        Mockito.when(x509Certificate.getExtensionValue(Extension.authorityInfoAccess.getId())).thenReturn(certificateToValidate.getEncoded());
        x509CertificateAuthorityInformationAccessValidator.validate(caCertificateValidationInfo);
        Mockito.verify(logger).error("AuthorityInformationAccess " + ErrorMessages.EXTENSION_NON_CRITICAL, " for CA {} ", caName);

    }
}
