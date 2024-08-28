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

import org.bouncycastle.asn1.x509.Extension;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectKeyIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common.CertificateExtensionUtils;

@RunWith(MockitoJUnitRunner.class)
public class X509CertificateSubjectKeyIdentifierValidatorTest {

    @InjectMocks
    X509CertificateSubjectKeyIdentifierValidator CertificateSubjectKeyIdentifierValidator;

    @Mock
    X509Certificate x509Cert;

    @Mock
    SubjectKeyIdentifier subjectKeyIdentifier;

    @Mock
    Logger logger;

    @Mock
    CertificateExtensionUtils certificateExtensionUtils;

    @Test
    public void validate() throws CertificateException, FileNotFoundException {
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("factory.crt");
        byte[] extensionValue = certificateToValidate.getExtensionValue(Extension.subjectKeyIdentifier.getId());
        Mockito.when(certificateExtensionUtils.getCertificateAttributeExtensionValue(certificateToValidate, Extension.subjectKeyIdentifier.getId())).thenReturn(extensionValue);
        CertificateSubjectKeyIdentifierValidator.validate(certificateBase.getRootCACertificateInfo(certificateToValidate));
    }
}
