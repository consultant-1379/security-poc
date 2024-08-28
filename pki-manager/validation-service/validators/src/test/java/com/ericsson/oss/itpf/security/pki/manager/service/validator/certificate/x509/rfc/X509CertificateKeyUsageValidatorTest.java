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

import static org.junit.Assert.*;

import java.io.FileNotFoundException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.HashSet;
import java.util.Set;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidKeyUsageExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.CAReIssueType;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.utils.X509CertificateUtility;

@RunWith(PowerMockRunner.class)
@PrepareForTest(X509CertificateUtility.class)
public class X509CertificateKeyUsageValidatorTest {

    @InjectMocks
    X509CertificateKeyUsageValidator certificateKeyUsageValidator;

    @Mock
    X509CertificateBasicConstraintsValidator certificateBasicConstraintsValidator;

    @Mock
    Logger logger;

    @Mock
    X509Certificate x509Certificate;

    @Mock
    BasicConstraints basicConstraints;

    static final String caName = "caName";

    @Test
    public void testValidate() throws CertificateException, FileNotFoundException {
        BasicConstraints basicConstraints = new BasicConstraints(true);
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificate = certificateBase.getX509Certificate("factory.crt");
        PowerMockito.mockStatic(X509CertificateUtility.class);
        Mockito.when(X509CertificateUtility.getBasicConstraints(certificate)).thenReturn(basicConstraints);
        certificateKeyUsageValidator.validate(certificateBase.getRootCACertificateInfo(certificate));
    }

    @Test(expected = InvalidKeyUsageExtension.class)
    public void testValidate_isCA() throws CertificateException, FileNotFoundException {
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificate = certificateBase.getX509Certificate("entity.crt");
        PowerMockito.mockStatic(X509CertificateUtility.class);
        certificateKeyUsageValidator.validate(certificateBase.getRootCACertificateInfo(certificate));

        Mockito.verify(logger).error(ErrorMessages.KEY_USAGE_EXTENSION_VALIDATION_FAILED + "for CA {}" + caName);

    }

    @Test(expected = InvalidKeyUsageExtension.class)
    public void testValidate_RFCException() throws CertificateException, FileNotFoundException {
        BasicConstraints basicConstraints = new BasicConstraints(false);
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificate = certificateBase.getX509Certificate("factory.crt");
        PowerMockito.mockStatic(X509CertificateUtility.class);
        Mockito.when(X509CertificateUtility.getBasicConstraints(certificate)).thenReturn(basicConstraints);
        certificateKeyUsageValidator.validate(certificateBase.getRootCACertificateInfo(certificate));
        Mockito.verify(logger).error("KeyCertSign is asserted but isCA in BasicConstraints is not asserted");
    }

    @Test(expected = InvalidKeyUsageExtension.class)
    public void validate_RFCException() throws CertificateException, FileNotFoundException {
        BasicConstraints basicConstraints = new BasicConstraints(false);
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");
        PowerMockito.mockStatic(X509CertificateUtility.class);
        Mockito.when(X509CertificateUtility.getBasicConstraints(certificate)).thenReturn(basicConstraints);
        certificateKeyUsageValidator.validate(certificateBase.getRootCACertificateInfo(certificate));
        Mockito.verify(logger).error("For CA, KeyCertSign,CRLSign,DigitalSignature keyUsagetypes are mandatory");
    }

    @Test
    public void testValidate_KeyUsageNull() throws CertificateException, FileNotFoundException {
        BasicConstraints basicConstraints = new BasicConstraints(false);
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificate = certificateBase.getX509Certificate("MyRoot.crt");
        PowerMockito.mockStatic(X509CertificateUtility.class);
        Mockito.when(X509CertificateUtility.getBasicConstraints(certificate)).thenReturn(basicConstraints);
        try {
            certificateKeyUsageValidator.validate(certificateBase.getRootCACertificateInfo(certificate));
            fail("testValidate_KeyUsageNull failed");
        } catch (Exception exception) {
            assertEquals(MissingMandatoryFieldException.class, exception.getClass());
            assertTrue((exception.getMessage()).contains(ErrorMessages.KEY_USAGE_MANDATORY_FOR_CA));
        }
    }

    @Test(expected = InvalidKeyUsageExtension.class)
    public void testValidate_KeyUsageType6() throws CertificateException, FileNotFoundException {
        boolean keyUsages[] = { false, false, false, false, false, true, false };

        Set<String> extensionOIDs = new HashSet<String>();
        extensionOIDs.add("2.5.29.15");
        Mockito.when(x509Certificate.getCriticalExtensionOIDs()).thenReturn(extensionOIDs);
        Mockito.when(x509Certificate.getKeyUsage()).thenReturn(keyUsages);
        CertificateBase certificateBase = new CertificateBase();
        certificateKeyUsageValidator.validate(certificateBase.getRootCACertificateInfo(x509Certificate));
        Mockito.verify(logger).error("For CA, KeyCertSign,CRLSign,DigitalSignature keyUsagetypes are mandatory");
    }

    @Test(expected = InvalidKeyUsageExtension.class)
    public void testValidate_isCritical() throws CertificateException, FileNotFoundException {
        boolean[] keyUsages = { true, false };
        CertificateBase certificateBase = new CertificateBase();
        Set<String> criticalExtensionOIDs = new HashSet<String>();
        criticalExtensionOIDs.add("2");
        Mockito.when(x509Certificate.getCriticalExtensionOIDs()).thenReturn(criticalExtensionOIDs);
        Mockito.when(x509Certificate.getKeyUsage()).thenReturn(keyUsages);
        PowerMockito.mockStatic(X509CertificateUtility.class);
        certificateKeyUsageValidator.validate(certificateBase.getRootCACertificateInfo(x509Certificate));
        Mockito.verify(logger).error(ErrorMessages.KEY_USAGE_EXTENSION_VALIDATION_FAILED + "for CA {}" + caName);

    }
}
