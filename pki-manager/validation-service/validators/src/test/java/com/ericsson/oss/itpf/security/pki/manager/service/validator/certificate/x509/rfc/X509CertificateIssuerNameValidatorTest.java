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

import javax.naming.InvalidNameException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.util.StringUtility;
import com.ericsson.oss.itpf.security.pki.common.util.constants.Constants;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.IssuerNotFoundException;

@RunWith(PowerMockRunner.class)
@PrepareForTest(StringUtility.class)
public class X509CertificateIssuerNameValidatorTest {
    @InjectMocks
    X509CertificateIssuerNameValidator certificateIssuerNameValidator;

    @Mock
    Logger logger;

    @Mock
    X509Certificate certificateToValidate;

    @Test
    public void testValidate() throws CertificateException, FileNotFoundException, InvalidNameException {
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");
        PowerMockito.mockStatic(StringUtility.class);
        final String issuerDN = certificateToValidate.getIssuerDN().getName();
        Mockito.when(StringUtility.getAttributeValueFromDN(issuerDN, Constants.COUNTRY_CODE_ATTRIBUTE)).thenReturn("SE");
        certificateIssuerNameValidator.validate(certificateBase.getRootCACertificateInfo(certificateToValidate));
    }

    @Test(expected = IssuerNotFoundException.class)
    public void testValidate_CountryLength() throws CertificateException, FileNotFoundException, InvalidNameException {
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");
        PowerMockito.mockStatic(StringUtility.class);
        final String issuerDN = certificateToValidate.getIssuerDN().getName();
        Mockito.when(StringUtility.getAttributeValueFromDN(issuerDN, Constants.COUNTRY_CODE_ATTRIBUTE)).thenReturn("SED");
        certificateIssuerNameValidator.validate(certificateBase.getRootCACertificateInfo(certificateToValidate));
        Mockito.verify(logger).error("Country Name Length is invalid(not 2)");
    }

    @SuppressWarnings("unchecked")
    @Test(expected = IssuerNotFoundException.class)
    public void testValidate_InvalidName() throws CertificateException, FileNotFoundException, InvalidNameException {
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");
        PowerMockito.mockStatic(StringUtility.class);
        final String issuerDN = certificateToValidate.getIssuerDN().getName();
        Mockito.when(StringUtility.getAttributeValueFromDN(issuerDN, Constants.COUNTRY_CODE_ATTRIBUTE)).thenThrow(InvalidNameException.class);
        certificateIssuerNameValidator.validate(certificateBase.getRootCACertificateInfo(certificateToValidate));
    }

    @Test(expected = IssuerNotFoundException.class)
    public void testValidate_IssuerDNNull() {
        Mockito.when(certificateToValidate.getIssuerDN()).thenReturn(null);
        CertificateBase certificateBase = new CertificateBase();
        certificateIssuerNameValidator.validate(certificateBase.getRootCACertificateInfo(certificateToValidate));
        Mockito.verify(logger).error("IssuerDN cannot be Null");
    }
}
