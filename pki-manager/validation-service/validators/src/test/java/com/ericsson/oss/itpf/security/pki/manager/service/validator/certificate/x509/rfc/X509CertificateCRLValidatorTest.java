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

import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.security.cert.*;

import javax.naming.InvalidNameException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.CAEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

@RunWith(MockitoJUnitRunner.class)
public class X509CertificateCRLValidatorTest {
    @InjectMocks
    X509CertificateCRLValidator certificatecRLValidator;

    @Mock
    CACertificatePersistenceHelper caCertificatePersistenceHelper;

    @Mock
    Logger logger;

    @Mock
    ExternalCRLInfoData externalCRLInfoData;

    @Mock
    X509CRL issuerX509CRL;

    @Mock
    X509Certificate x509Certificate;

    CAEntityData cAEntityData = new CAEntityData();
    private static final String CA_SUBJECT_NAME_PATH = "certificateAuthorityData.subjectDN";

    @Test
    public void testValidate() throws CertificateException, FileNotFoundException, CRLException {
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("factory.crt");
        String issuerDN = certificateToValidate.getIssuerDN().getName();
        cAEntityData.setExternalCA(true);
        cAEntityData.setCertificateAuthorityData(getCertificateAuthority("CA", true, "subject", "SAN"));

        Mockito.when(caCertificatePersistenceHelper.getCAEntity(issuerDN, CA_SUBJECT_NAME_PATH)).thenReturn(cAEntityData);

        Mockito.when(externalCRLInfoData.getCrl()).thenReturn(getCRL().getEncoded());
        certificatecRLValidator.validate(certificateBase.getRootCACertificateInfo(certificateToValidate));
    }

    @Test(expected = com.ericsson.oss.itpf.security.pki.manager.exception.CRLException.class)
    public void testValidate_CRLNull() throws CertificateException, FileNotFoundException {

        cAEntityData.setExternalCA(true);
        cAEntityData.setCertificateAuthorityData(getCertificateAuthority("CA", true, "subject", "SAN"));
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("factory.crt");

        String issuerDN = certificateToValidate.getIssuerDN().getName();
        Mockito.when(caCertificatePersistenceHelper.getCAEntity(issuerDN, CA_SUBJECT_NAME_PATH)).thenReturn(cAEntityData);

        certificatecRLValidator.validate(certificateBase.getRootCACertificateInfo(certificateToValidate));
        Mockito.verify(logger).error("CRL is empty");
    }

    @Test(expected = CANotFoundException.class)
    public void testValidate_CANull() throws CertificateException, FileNotFoundException {

        cAEntityData.setExternalCA(true);
        cAEntityData.setCertificateAuthorityData(getCertificateAuthority("CA", true, "subject", "SAN"));
        CertificateBase certificateBase = new CertificateBase();
        Mockito.when(caCertificatePersistenceHelper.getCAEntity("", CA_SUBJECT_NAME_PATH)).thenReturn(cAEntityData);
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("factory.crt");
        certificatecRLValidator.validate(certificateBase.getRootCACertificateInfo(certificateToValidate));
        Mockito.verify(logger).error(ErrorMessages.CA_ENTITY_NOT_FOUND);
    }

    @Test(expected = CAEntityException.class)
    public void testValidate_isExternalCA() throws CertificateException, FileNotFoundException {

        cAEntityData.setExternalCA(false);
        cAEntityData.setCertificateAuthorityData(getCertificateAuthority("CA", true, "subject", "SAN"));
        CertificateBase certificateBase = new CertificateBase();
        Mockito.when(caCertificatePersistenceHelper.getCAEntity("Factory Test CA", CA_SUBJECT_NAME_PATH)).thenReturn(cAEntityData);
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("factory.crt");
        certificatecRLValidator.validate(certificateBase.getRootCACertificateInfo(certificateToValidate));
        Mockito.verify(logger).error(ErrorMessages.CA_ENTITY_NOT_FOUND);
    }

    @SuppressWarnings("unchecked")
    @Test(expected = CAEntityException.class)
    public void validate_InvalidNameException() throws CertificateException, FileNotFoundException, CRLException {
        cAEntityData.setExternalCA(true);
        cAEntityData.setCertificateAuthorityData(getCertificateAuthority("CA", true, "subject", "SAN"));
        CertificateBase certificateBase = new CertificateBase();
        Mockito.when(caCertificatePersistenceHelper.getCAEntity("Factory Test CA", CA_SUBJECT_NAME_PATH)).thenThrow(InvalidNameException.class);
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("factory.crt");
        Mockito.when(externalCRLInfoData.getCrl()).thenReturn(getCRL().getEncoded());
        certificatecRLValidator.validate(certificateBase.getRootCACertificateInfo(certificateToValidate));
    }

    private CertificateAuthorityData getCertificateAuthority(final String name, final boolean isRootCA, final String subject, final String subjectAltName) {
        final CertificateAuthorityData certificateAuthority = new CertificateAuthorityData();
        certificateAuthority.setName(name);
        certificateAuthority.setRootCA(isRootCA);
        certificateAuthority.setExternalCrlInfoData(externalCRLInfoData);
        return certificateAuthority;
    }

    private X509CRL getCRL() throws CRLException, CertificateException, FileNotFoundException {
        final String cRLAbsolutePath = X509CertificateCRLValidatorTest.class.getResource("/Crls/VC_Root_CA_A1.crl").getPath();
        X509CRL x509CRL = generateCRLFromFactory(cRLAbsolutePath);

        return x509CRL;
    }

    private X509CRL generateCRLFromFactory(final String cRLfile) throws CertificateException, FileNotFoundException, CRLException {
        X509CRL x509CRL;
        CertificateFactory certificateFactory;
        certificateFactory = CertificateFactory.getInstance("x.509");
        final FileInputStream fileinputstream = new FileInputStream(cRLfile);
        x509CRL = (X509CRL) certificateFactory.generateCRL(fileinputstream);
        return x509CRL;
    }

}
