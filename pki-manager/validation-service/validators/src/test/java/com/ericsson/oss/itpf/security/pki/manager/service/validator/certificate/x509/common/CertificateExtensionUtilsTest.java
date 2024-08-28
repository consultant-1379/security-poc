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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.common;

import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateGenerationInfoData;

@RunWith(MockitoJUnitRunner.class)
public class CertificateExtensionUtilsTest {

    @InjectMocks
    CertificateExtensionUtils certificateExtensionUtils;

    @Mock
    X509Certificate x509Certificate;

    @Mock
    Logger logger;

    @Mock
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Mock
    CertificateGenerationInfoData certificateGenerationInfoData;
    @Mock
    ASN1ObjectIdentifier aSN1ObjectIdentifier;

    public static String attributeId = "2.5.29.19";
    public static String caName = "caName";

    @Test
    public void getCertificateAttributeExtensionValueTest() {
        Mockito.when(x509Certificate.getExtensionValue(attributeId)).thenReturn(new byte[] { 1 });
        certificateExtensionUtils.getCertificateAttributeExtensionValue(x509Certificate, attributeId);
    }

    @Test(expected = MissingMandatoryFieldException.class)
    public void getCertificateAttributeExtensionValueNullTest() {
        Mockito.when(x509Certificate.getExtensionValue(attributeId)).thenReturn(null);
        certificateExtensionUtils.getCertificateAttributeExtensionValue(x509Certificate, attributeId);
    }

}
