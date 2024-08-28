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
import java.security.*;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;

import javax.naming.InvalidNameException;
import javax.persistence.PersistenceException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.ExtCACertificatePersistanceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.IssuerNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

@RunWith(MockitoJUnitRunner.class)
public class X509CertificateSignatureValidatorTest {
    @InjectMocks
    X509CertificateSignatureValidator certificateSignatureValidator;

    @Mock
    X509Certificate x509Certificate;

    @Mock
    Logger logger;

    @Mock
    PublicKey publicKey;

    @Mock
    Certificate certificate;

    @Mock
    ExtCACertificatePersistanceHandler extCACertificatePersistanceHandler;

    public static X509Certificate x509CACertificate;

    public static CACertificateValidationInfo cACertificateValidationInfo;

    public static String issuerName = "Factory Test CA";
    public static List<Certificate> certificates;
    CertificateBase certificateBase;

    private static String caName = "caName";

    public void setupData() throws CertificateException, FileNotFoundException {
        certificateBase = new CertificateBase();
        x509CACertificate = certificateBase.getX509Certificate("factory.crt");

        Certificate cert = new Certificate();
        cert.setX509Certificate(x509CACertificate);
        certificates = new ArrayList<Certificate>();
        certificates.add(cert);
        cACertificateValidationInfo = new CACertificateValidationInfo();
        cACertificateValidationInfo.setCaName("Factory Test CA");
        cACertificateValidationInfo.setCertificate(x509CACertificate);

    }

    @Test
    public void testValidate() throws CertificateException, PersistenceException, IOException {

        setupData();

        Mockito.when(x509Certificate.getIssuerDN()).thenReturn(x509CACertificate.getIssuerDN());
        Mockito.when(extCACertificatePersistanceHandler.getIssuerX509Certificate(x509CACertificate)).thenReturn(x509CACertificate);

        certificateSignatureValidator.validate(cACertificateValidationInfo);
    }

    @Test(expected = IssuerNotFoundException.class)
    public void testValidate_WrongAlgorithm() throws CertificateException, PersistenceException, IOException {
        CertificateBase certificateBase = new CertificateBase();
        x509CACertificate = certificateBase.getX509Certificate("factory.crt");
        Certificate cert = new Certificate();
        cert.setX509Certificate(x509CACertificate);
        List<Certificate> certificates = new ArrayList<Certificate>();
        certificates.add(cert);
        CACertificateValidationInfo cACertificateValidationInfo = new CACertificateValidationInfo();
        cACertificateValidationInfo.setCaName("Factory Test CA");
        cACertificateValidationInfo.setCertificate(x509Certificate);

        Mockito.when(x509Certificate.getIssuerDN()).thenReturn(x509CACertificate.getIssuerDN());

        Mockito.when(x509Certificate.getSigAlgName()).thenThrow(NoSuchAlgorithmException.class);

        Mockito.when(extCACertificatePersistanceHandler.getCertificatesForExtCA("Factory Test CA", CertificateStatus.ACTIVE)).thenReturn(certificates);

        certificateSignatureValidator.validate(cACertificateValidationInfo);

        logger.error(ErrorMessages.ALGORITHM_IS_NOT_FOUND, " for CA {} ", caName, (String) Matchers.anyObject());

    }

    @Test(expected = IssuerNotFoundException.class)
    public void testValidate_WrongKey() throws CertificateException, PersistenceException, IOException {

        CertificateBase certificateBase = new CertificateBase();
        x509CACertificate = certificateBase.getX509Certificate("factory.crt");
        String issuerName = "Factory Test CA";
        Certificate cert = new Certificate();
        cert.setX509Certificate(x509CACertificate);
        List<Certificate> certificates = new ArrayList<Certificate>();
        certificates.add(cert);
        CACertificateValidationInfo cACertificateValidationInfo = new CACertificateValidationInfo();
        cACertificateValidationInfo.setCaName("Factory Test CA");
        cACertificateValidationInfo.setCertificate(x509Certificate);

        Mockito.when(x509Certificate.getIssuerDN()).thenReturn(x509CACertificate.getIssuerDN());
        Mockito.when(x509Certificate.getSigAlgName()).thenThrow(InvalidKeyException.class);

        Mockito.when(extCACertificatePersistanceHandler.getCertificatesForExtCA(issuerName, CertificateStatus.ACTIVE)).thenReturn(certificates);

        certificateSignatureValidator.validate(cACertificateValidationInfo);

        Mockito.verify(logger).error(ErrorMessages.INVALID_PUBLIC_KEY, " for CA {} ", caName, (String) Matchers.anyObject());

    }

    @Test(expected = IssuerNotFoundException.class)
    public void testValidate_SignatureException() throws CertificateException, PersistenceException, IOException {
        CertificateBase certificateBase = new CertificateBase();
        x509CACertificate = certificateBase.getX509Certificate("factory.crt");
        String issuerName = "Factory Test CA";
        Certificate cert = new Certificate();
        cert.setX509Certificate(x509CACertificate);
        List<Certificate> certificates = new ArrayList<Certificate>();
        certificates.add(cert);
        CACertificateValidationInfo cACertificateValidationInfo = new CACertificateValidationInfo();
        cACertificateValidationInfo.setCaName("Factory Test CA");
        cACertificateValidationInfo.setCertificate(x509Certificate);

        Mockito.when(extCACertificatePersistanceHandler.getCertificatesForExtCA(issuerName, CertificateStatus.ACTIVE)).thenReturn(certificates);
        Mockito.when(x509Certificate.getIssuerDN()).thenReturn(x509CACertificate.getIssuerDN());
        Mockito.when(x509Certificate.getSigAlgName()).thenThrow(SignatureException.class);

        certificateSignatureValidator.validate(cACertificateValidationInfo);

        Mockito.verify(logger).error(ErrorMessages.INVALID_SIGNATURE, " for CA {} ", caName, (String) Matchers.anyObject());

    }

    @Test(expected = IssuerNotFoundException.class)
    public void testValidate_EncodingException() throws CertificateException, PersistenceException, IOException {

        CertificateBase certificateBase = new CertificateBase();
        x509CACertificate = certificateBase.getX509Certificate("factory.crt");
        String issuerName = "Factory Test CA";
        Certificate cert = new Certificate();
        cert.setX509Certificate(x509CACertificate);
        List<Certificate> certificates = new ArrayList<Certificate>();
        certificates.add(cert);
        CACertificateValidationInfo cACertificateValidationInfo = new CACertificateValidationInfo();
        cACertificateValidationInfo.setCaName("Factory Test CA");
        cACertificateValidationInfo.setCertificate(x509Certificate);

        Mockito.when(extCACertificatePersistanceHandler.getCertificatesForExtCA(issuerName, CertificateStatus.ACTIVE)).thenReturn(certificates);
        Mockito.when(x509Certificate.getIssuerDN()).thenReturn(x509CACertificate.getIssuerDN());
        Mockito.when(x509Certificate.getSigAlgName()).thenThrow(CertificateEncodingException.class);

        certificateSignatureValidator.validate(cACertificateValidationInfo);

        Mockito.verify(logger).error(ErrorMessages.CERTIFICATE_ENCODING_FAILED, " for CA {} ", caName, (String) Matchers.anyObject());

    }

    @Test(expected = PersistenceException.class)
    public void testValidate_PersistenceException() throws CertificateException, PersistenceException, IOException {

        CertificateBase certificateBase = new CertificateBase();
        x509CACertificate = certificateBase.getX509Certificate("factory.crt");
        String issuerName = "Factory Test CA";
        Certificate cert = new Certificate();
        cert.setX509Certificate(x509CACertificate);
        List<Certificate> certificates = new ArrayList<Certificate>();
        certificates.add(cert);
        CACertificateValidationInfo cACertificateValidationInfo = new CACertificateValidationInfo();
        cACertificateValidationInfo.setCaName("Factory Test CA");
        cACertificateValidationInfo.setCertificate(x509Certificate);
        Mockito.when(x509Certificate.getIssuerDN()).thenReturn(x509CACertificate.getIssuerDN());
        Mockito.when(extCACertificatePersistanceHandler.getCertificatesForExtCA(x509Certificate.getIssuerDN().getName(), CertificateStatus.ACTIVE)).thenReturn(certificates);
        Mockito.when(x509Certificate.getIssuerDN()).thenReturn(x509CACertificate.getIssuerDN());
        Mockito.when(x509Certificate.getSigAlgName()).thenThrow(PersistenceException.class);

        certificateSignatureValidator.validate(cACertificateValidationInfo);
        Mockito.verify(logger).error(ErrorMessages.DB_EXCEPTION, " for CA {} ", caName, (String) Matchers.anyObject());
    }

    @Test(expected = IssuerNotFoundException.class)
    public void testValidate_CertificateException() throws CertificateException, PersistenceException, IOException {

        CertificateBase certificateBase = new CertificateBase();
        x509CACertificate = certificateBase.getX509Certificate("factory.crt");
        String issuerName = "Factory Test CA";
        Certificate cert = new Certificate();
        cert.setX509Certificate(x509CACertificate);
        List<Certificate> certificates = new ArrayList<Certificate>();
        certificates.add(cert);
        CACertificateValidationInfo cACertificateValidationInfo = new CACertificateValidationInfo();
        cACertificateValidationInfo.setCaName("Factory Test CA");
        cACertificateValidationInfo.setCertificate(x509Certificate);

        Mockito.when(extCACertificatePersistanceHandler.getCertificatesForExtCA(issuerName, CertificateStatus.ACTIVE)).thenReturn(certificates);
        Mockito.when(x509Certificate.getIssuerDN()).thenReturn(x509CACertificate.getIssuerDN());
        Mockito.when(x509Certificate.getSigAlgName()).thenThrow(CertificateException.class);

        certificateSignatureValidator.validate(cACertificateValidationInfo);

        Mockito.verify(logger).error(ErrorMessages.CERTIFICATE_NOT_FOUND, " for CA {} ", caName);

    }

    @Test(expected = IssuerNotFoundException.class)
    public void testValidate_CertificateExcepn() throws CertificateException, PersistenceException, IOException {

        CertificateBase certificateBase = new CertificateBase();
        x509CACertificate = certificateBase.getX509Certificate("factory.crt");
        String issuerName = "Factory Test CA";
        Certificate cert = new Certificate();
        cert.setX509Certificate(x509CACertificate);
        List<Certificate> certificates = new ArrayList<Certificate>();
        CACertificateValidationInfo cACertificateValidationInfo = new CACertificateValidationInfo();
        cACertificateValidationInfo.setCaName("Factory Test CA");
        cACertificateValidationInfo.setCertificate(x509Certificate);

        Mockito.when(extCACertificatePersistanceHandler.getIssuerX509Certificate(x509Certificate)).thenThrow(CertificateNotFoundException.class);
        Mockito.when(x509Certificate.getIssuerDN()).thenReturn(x509CACertificate.getIssuerDN());

        certificateSignatureValidator.validate(cACertificateValidationInfo);

        Mockito.verify(logger).error(ErrorMessages.ISSUER_CERTIFICATE_NOT_FOUND, " for CA {} ");

    }
}
