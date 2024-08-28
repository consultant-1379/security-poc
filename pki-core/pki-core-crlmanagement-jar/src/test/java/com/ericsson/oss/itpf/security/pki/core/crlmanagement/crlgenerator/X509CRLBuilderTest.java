/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.core.crlmanagement.crlgenerator;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.Date;
import java.util.List;

import javax.security.auth.x500.X500Principal;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.SubjectPublicKeyInfo;
import org.bouncycastle.cert.jcajce.JcaX509CRLConverter;
import org.bouncycastle.operator.OperatorCreationException;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.internal.stubbing.answers.ThrowsException;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.kaps.api.KeyAccessProviderService;
import com.ericsson.oss.itpf.security.kaps.crl.exception.InvalidCRLExtensionsException;
import com.ericsson.oss.itpf.security.kaps.crl.exception.SignCRLException;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyIdentifierNotFoundException;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.kaps.model.holder.X509CRLHolder;
import com.ericsson.oss.itpf.security.kaps.model.holder.X509v2CRLBuilderHolder;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AuthorityKeyIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.builder.AuthorityInformationAccessBuilder;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.builder.AuthorityKeyIdentifierBuilder;
import com.ericsson.oss.itpf.security.pki.core.common.eserviceproxy.KeyAccessProviderServiceProxy;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CertificateAuthorityModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.core.common.utils.DateUtil;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.builder.IssuingDistributionPointsBuilder;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.common.test.CRLSetUpData;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLGenerationException;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.KeyPairGenerationException;

/**
 * Test Class for X509CRLBuilder.
 */
@RunWith(MockitoJUnitRunner.class)
public class X509CRLBuilderTest {

    @InjectMocks
    X509CRLBuilder x509CRLBuilder;

    @Mock
    X509CRLBuilder x509CRLBuilderMock;

    @Mock
    DateUtil dateUtil;

    @Mock
    AuthorityKeyIdentifierBuilder authorityKeyIdentifierBuilder;

    @Mock
    IssuingDistributionPointsBuilder issuingDistributionPointsBuilder;

    @Mock
    AuthorityInformationAccessBuilder authorityInformationAccessBuilder;

    @Mock
    CertificatePersistenceHelper persistenceHelper;

    @Mock
    CertificateAuthorityModelMapper authorityModelMapper;

    @Mock
    CertificateModelMapper certificateModelMapper;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    Logger logger;

    @Mock
    JcaX509CRLConverter jcaX509CRLConverter;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    KeyAccessProviderService keyAccessProviderService;

    @Mock
    KeyAccessProviderServiceProxy keyAccessProviderServiceProxy;

    private static CertificateAuthority certificateAuthority;
    private static Certificate issuerCertificate;
    private static List<RevokedCertificatesInfo> revokedCertificateInfoList;
    private static CrlGenerationInfo mappedCrlGenerationInfo;
    private static CRLNumber cRLNumber;
    private static Date thisUpdate;
    private static KeyIdentifier keyIdentifier;
    private static X509CRL x509CRL;
    private static X509CRLHolder x509crlHolder;
    public static final ASN1ObjectIdentifier biometricInfo = new ASN1ObjectIdentifier("1.3.6.1.5.5.7.1.2");
    private AuthorityKeyIdentifier authorityKeyIdentifier;
    private static KeyPair keyPair;
    private static PublicKey publickey;

    /**
     * Prepares initial Data.
     * 
     * @throws IOException
     * @throws CertificateException
     * @throws NoSuchAlgorithmException
     * @throws CRLException
     * 
     */
    @Before
    public void setUpData() throws CertificateException, IOException, NoSuchAlgorithmException, CRLException {
        authorityKeyIdentifier = new AuthorityKeyIdentifier();
        authorityKeyIdentifier.setCritical(true);
        final KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPair = keyPairGenerator.generateKeyPair();
        publickey = keyPair.getPublic();
        keyIdentifier = new KeyIdentifier();
        keyIdentifier.setId("RSA");
        thisUpdate = CRLSetUpData.getNextAfter();
        certificateAuthority = CRLSetUpData.getCertificateAuthority();
        issuerCertificate = CRLSetUpData.getCertificate();
        issuerCertificate.setX509Certificate(CRLSetUpData.getX509Certificate("src/test/resources/MyRoot.crt"));
        revokedCertificateInfoList = CRLSetUpData.getRevokedCertificatesInfoList();
        mappedCrlGenerationInfo = CRLSetUpData.getCrlGenerationInfo();
        mappedCrlGenerationInfo.setSignatureAlgorithm(getAlgorithm());
        mappedCrlGenerationInfo.getCrlExtensions().setCrlNumber(CRLSetUpData.getCRLNumber());
        mappedCrlGenerationInfo.getCrlExtensions().setIssuingDistributionPoint(null);
        cRLNumber = CRLSetUpData.getCRLNumber();
        x509crlHolder = new X509CRLHolder();

        Mockito.when(keyAccessProviderServiceProxy.getKeyAccessProviderService()).thenReturn(keyAccessProviderService);
    }

    /**
     * Method to test build.
     *
     * @throws CertificateException
     * @throws CRLException
     * @throws InvalidCRLExtensionsException
     * @throws IOException
     * @throws KeyAccessProviderServiceException
     * @throws KeyIdentifierNotFoundException
     * @throws KeyPairGenerationException
     * @throws OperatorCreationException
     * @throws SignCRLException
     */
    @SuppressWarnings("deprecation")
    @Test
    public void testBuild() throws CertificateException, CRLException, InvalidCRLExtensionsException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException, KeyPairGenerationException, OperatorCreationException, SignCRLException {
        byte[] value = new byte[123];
        org.bouncycastle.asn1.x509.Extension informationExtension = new org.bouncycastle.asn1.x509.Extension(org.bouncycastle.asn1.x509.Extension.authorityInfoAccess, true, value);
        Extension extension1 = null;
        DEROctetString authorityKeyIdentifierExtension = null;
        @SuppressWarnings("resource")
        final SubjectPublicKeyInfo apki = new SubjectPublicKeyInfo((ASN1Sequence) new ASN1InputStream(new ByteArrayInputStream(publickey.getEncoded())).readObject());
        authorityKeyIdentifierExtension = new DEROctetString(new org.bouncycastle.asn1.x509.AuthorityKeyIdentifier(apki));
        extension1 = new Extension(Extension.authorityKeyIdentifier, authorityKeyIdentifier.isCritical(), authorityKeyIdentifierExtension);

        Mockito.when(
                authorityKeyIdentifierBuilder.buildAuthorityIdentifier((CertificateGenerationInfo) Mockito.anyObject(), (CertificateExtension) Mockito.anyObject(), (PublicKey) Mockito.anyObject(),
                        Mockito.anyString())).thenReturn(extension1);
        Mockito.when(authorityInformationAccessBuilder.buildAuthorityInformationAccess(mappedCrlGenerationInfo.getCrlExtensions().getAuthorityInformationAccess())).thenReturn(informationExtension);
        Mockito.when(certificatePersistenceHelper.getKeyIdentifier(certificateAuthority.getName())).thenReturn(keyIdentifier);
        Mockito.when(dateUtil.getCurrentDate()).thenReturn(thisUpdate);
        Mockito.when(dateUtil.addDurationToDate(thisUpdate, mappedCrlGenerationInfo.getValidityPeriod())).thenReturn(thisUpdate);
        Mockito.when(keyAccessProviderService.signCRL((KeyIdentifier) Mockito.anyObject(), Mockito.anyString(), (X509v2CRLBuilderHolder) Mockito.anyObject(), (X500Principal) Mockito.anyObject())).thenReturn(getX509CRLHolder());
        X509CRL ExpectedX509CRL = x509CRLBuilder.build(certificateAuthority, issuerCertificate, revokedCertificateInfoList, mappedCrlGenerationInfo, cRLNumber);
        assertNotNull(ExpectedX509CRL);
        assertEquals("SHA256withRSA", ExpectedX509CRL.getSigAlgName());
        assertEquals(2, ExpectedX509CRL.getVersion());
    }

    /**
     * Method to test Occurrence of CRLServiceException
     *
     * @throws CertificateException
     * @throws CRLException
     * @throws InvalidCRLExtensionsException
     * @throws IOException
     * @throws KeyAccessProviderServiceException
     * @throws KeyIdentifierNotFoundException
     * @throws KeyPairGenerationException
     * @throws OperatorCreationException
     * @throws SignCRLException
     */
    @SuppressWarnings("unchecked")
    @Test(expected = CRLServiceException.class)
    public void testBuild_CRLServiceException() throws CertificateException, CRLException, InvalidCRLExtensionsException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException, KeyPairGenerationException, OperatorCreationException, SignCRLException {
        mappedCrlGenerationInfo.getCrlExtensions().setAuthorityKeyIdentifier(null);
        mappedCrlGenerationInfo.getCrlExtensions().setIssuingDistributionPoint(null);
        Mockito.when(certificatePersistenceHelper.getKeyIdentifier(certificateAuthority.getName())).thenReturn(keyIdentifier);
        Mockito.when(dateUtil.getCurrentDate()).thenReturn(thisUpdate);
        Mockito.when(dateUtil.addDurationToDate(thisUpdate, mappedCrlGenerationInfo.getValidityPeriod())).thenReturn(thisUpdate);
        Mockito.when(keyAccessProviderService.signCRL((KeyIdentifier) Mockito.anyObject(), Mockito.anyString(), (X509v2CRLBuilderHolder) Mockito.anyObject(), (X500Principal) Mockito.anyObject())).thenThrow(
                com.ericsson.oss.itpf.security.kaps.crl.exception.SignCRLException.class);
        x509CRLBuilder.build(certificateAuthority, issuerCertificate, revokedCertificateInfoList, mappedCrlGenerationInfo, cRLNumber);
    }

    /**
     * Method to test Occurrence of InvalidCRLExtensionsException.
     *
     * @throws CertificateException
     * @throws CRLException
     * @throws InvalidCRLExtensionsException
     * @throws IOException
     * @throws KeyAccessProviderServiceException
     * @throws KeyIdentifierNotFoundException
     * @throws KeyPairGenerationException
     * @throws OperatorCreationException
     * @throws SignCRLException
     */
    @SuppressWarnings("unchecked")
    @Test(expected = CRLGenerationException.class)
    public void testBuild_InvalidCRLExtensionsException() throws CertificateException, CRLException, InvalidCRLExtensionsException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException, KeyPairGenerationException, OperatorCreationException, SignCRLException {
        mappedCrlGenerationInfo.getCrlExtensions().setAuthorityKeyIdentifier(null);
        mappedCrlGenerationInfo.getCrlExtensions().setIssuingDistributionPoint(null);
        Mockito.when(certificatePersistenceHelper.getKeyIdentifier(certificateAuthority.getName())).thenReturn(keyIdentifier);
        Mockito.when(dateUtil.getCurrentDate()).thenReturn(thisUpdate);
        Mockito.when(dateUtil.addDurationToDate(thisUpdate, mappedCrlGenerationInfo.getValidityPeriod())).thenReturn(thisUpdate);
        Mockito.when(keyAccessProviderService.signCRL((KeyIdentifier) Mockito.anyObject(), Mockito.anyString(), (X509v2CRLBuilderHolder) Mockito.anyObject(), (X500Principal) Mockito.anyObject())).thenThrow(
                com.ericsson.oss.itpf.security.kaps.crl.exception.InvalidCRLExtensionsException.class);
        x509CRLBuilder.build(certificateAuthority, issuerCertificate, revokedCertificateInfoList, mappedCrlGenerationInfo, cRLNumber);
    }

    /**
     * Method to test Occurrence of CRLServiceException.
     *
     * @throws CertificateException
     * @throws CRLException
     * @throws InvalidCRLExtensionsException
     * @throws IOException
     * @throws KeyAccessProviderServiceException
     * @throws KeyIdentifierNotFoundException
     * @throws KeyPairGenerationException
     * @throws OperatorCreationException
     * @throws SignCRLException
     */
    @SuppressWarnings("unchecked")
    @Test(expected = CRLGenerationException.class)
    public void testBuild_CertificateException() throws CertificateException, CRLException, InvalidCRLExtensionsException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException, KeyPairGenerationException, OperatorCreationException, SignCRLException {
        mappedCrlGenerationInfo.getCrlExtensions().setAuthorityKeyIdentifier(null);
        mappedCrlGenerationInfo.getCrlExtensions().setIssuingDistributionPoint(null);
        Mockito.when(certificatePersistenceHelper.getKeyIdentifier(certificateAuthority.getName())).thenReturn(keyIdentifier);
        Mockito.when(dateUtil.getCurrentDate()).thenReturn(thisUpdate);
        Mockito.when(dateUtil.addDurationToDate(thisUpdate, mappedCrlGenerationInfo.getValidityPeriod())).thenReturn(thisUpdate);
        Mockito.when(keyAccessProviderService.signCRL((KeyIdentifier) Mockito.anyObject(), Mockito.anyString(), (X509v2CRLBuilderHolder) Mockito.anyObject(), (X500Principal) Mockito.anyObject())).thenThrow(CertificateException.class);
        x509CRLBuilder.build(certificateAuthority, issuerCertificate, revokedCertificateInfoList, mappedCrlGenerationInfo, cRLNumber);
    }

    /**
     * Method to get Algorithm.
     * 
     * @return Algorithm.
     */
    private Algorithm getAlgorithm() {
        final Algorithm signatureAlgorithm = new Algorithm();
        signatureAlgorithm.setName("SHA256withRSA");
        return signatureAlgorithm;
    }


    /**
     * Method to get X509CRLHolder.
     * 
     * @return X509CRLHolder.
     */
    private X509CRLHolder getX509CRLHolder() throws CertificateException, CRLException, IOException {
        x509CRL = CRLSetUpData.getX509CRL("src/test/resources/test1_123.crl");
        x509crlHolder.setCrlBytes(x509CRL.getEncoded());
        return x509crlHolder;
    }
}
