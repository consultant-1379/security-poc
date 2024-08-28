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
import org.junit.Ignore;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidAuthorityKeyIdentifierExtension;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CertificateExtensionUtils;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

@RunWith(MockitoJUnitRunner.class)
public class X509CertificateAuthorityKeyIdentifierValidatorTest {

    @InjectMocks
    X509CertificateAuthorityKeyIdentifierValidator x509CertificateAuthorityKeyIdentifierValidator;

    @Mock
    CACertificateValidationInfo caCertificateValidationInfo;

    @Mock
    X509Certificate x509Certificate;

    @Mock
    Logger logger;

    @Mock
    CertificateExtensionUtils certificateExtensionUtils;

    static final String caName = "caName";

    @Test
    public void testValidate() throws CertificateException, FileNotFoundException {
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ARJ_Root.crt");

        Mockito.when(caCertificateValidationInfo.getCertificate()).thenReturn(certificateToValidate);
        Mockito.when(caCertificateValidationInfo.getCaName()).thenReturn(caName);
        byte[] extensionValue = certificateToValidate.getExtensionValue(Extension.authorityKeyIdentifier.getId());
        Mockito.when(certificateExtensionUtils.getCertificateAttributeExtensionValue(certificateToValidate, Extension.authorityKeyIdentifier.getId())).thenReturn(extensionValue);
        x509CertificateAuthorityKeyIdentifierValidator.validate(caCertificateValidationInfo);

        Mockito.verify(logger).debug("Validating X509Certificate AuthorityKeyIdentifier for CA {} ", caName);

    }


    @Test(expected = NullPointerException.class)
    public void testValidate_extensionValueNull() throws CertificateException, FileNotFoundException {

        Mockito.when(caCertificateValidationInfo.getCertificate()).thenReturn(x509Certificate);
        Mockito.when(caCertificateValidationInfo.getCaName()).thenReturn(caName);

        Mockito.when(x509Certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId())).thenReturn(null);

        x509CertificateAuthorityKeyIdentifierValidator.validate(caCertificateValidationInfo);

        Mockito.verify(logger).error(" AuthorityKeyIdentifier Extension: " + ErrorMessages.EXTENSION_CRITICAL + "for CA {} ", caName);

    }

    @Test(expected = InvalidAuthorityKeyIdentifierExtension.class)
    public void testValidate_ExtensionCritical() throws CertificateException, FileNotFoundException {
        final Set<String> criticalExtensionOIDs = new HashSet<String>();
        final byte[] extensionValue = new byte[] { 1 };
        criticalExtensionOIDs.add("2.5.29.35");

        Mockito.when(caCertificateValidationInfo.getCertificate()).thenReturn(x509Certificate);
        Mockito.when(caCertificateValidationInfo.getCaName()).thenReturn(caName);

        Mockito.when(x509Certificate.getCriticalExtensionOIDs()).thenReturn(criticalExtensionOIDs);

        Mockito.when(x509Certificate.getExtensionValue(Extension.authorityKeyIdentifier.getId())).thenReturn(extensionValue);

        x509CertificateAuthorityKeyIdentifierValidator.validate(caCertificateValidationInfo);

        Mockito.verify(logger).error(" AuthorityKeyIdentifier Extension: " + ErrorMessages.EXTENSION_NON_CRITICAL + "for CA {} ", caName);
    }

}
