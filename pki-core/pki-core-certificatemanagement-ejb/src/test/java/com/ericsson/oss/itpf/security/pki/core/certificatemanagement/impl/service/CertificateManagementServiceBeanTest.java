/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.impl.service;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x500.X500NameBuilder;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.bouncycastle.pkcs.PKCS10CertificationRequestBuilder;
import org.bouncycastle.pkcs.jcajce.JcaPKCS10CertificationRequestBuilder;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.impl.*;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CertificatePersistenceHelper;

@RunWith(MockitoJUnitRunner.class)
public class CertificateManagementServiceBeanTest {

    @InjectMocks
    private CertificateManagementServiceBean certificateManagementServiceBean;

    @Mock
    private CertificateManagerFactory certificateManagerFactory;

    @Mock
    private CAEntityCertificateManager caEntityCertificateManager;

    @Mock
    private EntityCertificateManager entityCertificateManager;
    
    @Mock
    private ImportCertificateManager importCertificateManager;

    @Mock
    private CSRManager csrManager;

    private X509Certificate x509Certificate;

    @Spy
    Logger logger = LoggerFactory.getLogger(CertificateManagementServiceBean.class);

    @Mock
    private CertificatePersistenceHelper persistenceHelper;

    private CertificateGenerationInfo certificateGenerationInfo;
    private Certificate certificate;
    private PKCS10CertificationRequestHolder certificationRequestHolder;
    private PKCS10CertificationRequest pkcs10CertificationRequest;

    private static final String SIGNATURE_ALGORITHM = "SHA1withRSA";
    private static final String PROVIDER = "BC";
    public static final String KEY_GEN_ALGORITHM = "RSA";
    public final static String ROOT_CA = "ENM_RootCA";

    /**
     * Prepares initial data.
     * 
     * @throws IOException
     * @throws OperatorCreationException
     * @throws NoSuchProviderException
     * @throws SignatureException
     * @throws NoSuchAlgorithmException
     * @throws InvalidKeyException
     */
    @Before
    public void setUp() throws InvalidKeyException, NoSuchAlgorithmException, SignatureException, NoSuchProviderException, OperatorCreationException, IOException {

        Security.addProvider(new BouncyCastleProvider());

        certificateGenerationInfo = new CertificateGenerationInfo();
        certificateGenerationInfo.setRequestType(RequestType.NEW);

        final Calendar notBefore = Calendar.getInstance();
        final Calendar notAfter = notBefore;
        notAfter.add(Calendar.DAY_OF_MONTH, 2);

        certificate = new Certificate();
        certificate.setId(1);
        certificate.setSerialNumber("1234546");
        certificate.setStatus(CertificateStatus.ACTIVE);
        certificate.setNotBefore(notBefore.getTime());
        certificate.setNotAfter(notAfter.getTime());
        certificate.setIssuedTime(notBefore.getTime());

        GeneralName[] subjectAltName = new GeneralName[2];
        subjectAltName[0] = new GeneralName(GeneralName.dNSName, "abc.com");
        subjectAltName[1] = new GeneralName(GeneralName.directoryName, "CN=dir");

        pkcs10CertificationRequest = generatePKCS10Request(Arrays.asList(subjectAltName));

        certificationRequestHolder = new PKCS10CertificationRequestHolder(pkcs10CertificationRequest);
    }

    /**
     * Test method for generation of CA entity certificate.
     * 
     * @throws CertificateException
     *             thrown incase of failures in generating certificate.
     */
    @Test
    public void testCreateCertificateForCA() throws CertificateException {

        Mockito.when(certificateManagerFactory.getManager(certificateGenerationInfo)).thenReturn(caEntityCertificateManager);

        Mockito.when(caEntityCertificateManager.generateCertificate(certificateGenerationInfo)).thenReturn(certificate);

        final Certificate cert = certificateManagementServiceBean.createCertificate(certificateGenerationInfo);

        assertNotNull(certificate);
        assertEquals(certificate.getId(), cert.getId());
        assertEquals(certificate.getSerialNumber(), cert.getSerialNumber());
        assertEquals(certificate.getStatus(), cert.getStatus());
        assertEquals(certificate.getNotAfter(), cert.getNotAfter());
        assertEquals(certificate.getNotBefore(), cert.getNotBefore());
        assertEquals(certificate.getIssuedTime(), cert.getIssuedTime());
    }

    /**
     * Test method for generation of Entity certificate.
     * 
     * @throws CertificateException
     *             thrown incase of failures in generating certificate.
     */
    @Test
    public void testCreateCertificateForEntity() throws CertificateException {

        Mockito.when(certificateManagerFactory.getManager(certificateGenerationInfo)).thenReturn(entityCertificateManager);

        Mockito.when(entityCertificateManager.generateCertificate(certificateGenerationInfo)).thenReturn(certificate);

        final Certificate cert = certificateManagementServiceBean.createCertificate(certificateGenerationInfo);

        assertNotNull(certificate);
        assertEquals(certificate.getId(), cert.getId());
        assertEquals(certificate.getSerialNumber(), cert.getSerialNumber());
        assertEquals(certificate.getStatus(), cert.getStatus());
        assertEquals(certificate.getNotAfter(), cert.getNotAfter());
        assertEquals(certificate.getNotBefore(), cert.getNotBefore());
        assertEquals(certificate.getIssuedTime(), cert.getIssuedTime());
    }

    /**
     * Test method for renewal of CA certificate.
     * 
     * @throws CertificateException
     *             thrown incase of failures in generating certificate.
     */
    @Test
    public void testRenewCertificateForCA() throws CertificateException {

        Mockito.when(certificateManagerFactory.getManager(certificateGenerationInfo)).thenReturn(caEntityCertificateManager);

        Mockito.when(caEntityCertificateManager.generateCertificate(certificateGenerationInfo)).thenReturn(certificate);

        final Certificate cert = certificateManagementServiceBean.renewCertificate(certificateGenerationInfo);

        assertNotNull(certificate);
        assertEquals(certificate.getId(), cert.getId());
        assertEquals(certificate.getSerialNumber(), cert.getSerialNumber());
        assertEquals(certificate.getStatus(), cert.getStatus());
        assertEquals(certificate.getNotAfter(), cert.getNotAfter());
        assertEquals(certificate.getNotBefore(), cert.getNotBefore());
        assertEquals(certificate.getIssuedTime(), cert.getIssuedTime());
    }

    /**
     * Test method for rekey of CA certificate.
     * 
     * @throws CertificateException
     *             thrown incase of failures in generating certificate.
     */
    @Test
    public void testRekeyCertificateForCA() throws CertificateException {

        Mockito.when(certificateManagerFactory.getManager(certificateGenerationInfo)).thenReturn(caEntityCertificateManager);

        Mockito.when(caEntityCertificateManager.generateCertificate(certificateGenerationInfo)).thenReturn(certificate);

        final Certificate cert = certificateManagementServiceBean.reKeyCertificate(certificateGenerationInfo);

        assertNotNull(certificate);
        assertEquals(certificate.getId(), cert.getId());
        assertEquals(certificate.getSerialNumber(), cert.getSerialNumber());
        assertEquals(certificate.getStatus(), cert.getStatus());
        assertEquals(certificate.getNotAfter(), cert.getNotAfter());
        assertEquals(certificate.getNotBefore(), cert.getNotBefore());
        assertEquals(certificate.getIssuedTime(), cert.getIssuedTime());
    }

    /**
     * Test method to check update of certificates status to expired.
     */
    @Test
    public void testUpdateCertificateStatusToExpired() {

        Mockito.doNothing().when(persistenceHelper).updateCertificateStatusToExpired();

        certificateManagementServiceBean.updateCertificateStatusToExpired();

        Mockito.verify(persistenceHelper).updateCertificateStatusToExpired();
    }

    @Test
    public void testExportCSR() {

        Mockito.when(certificateManagementServiceBean.generateCSR(certificateGenerationInfo)).thenReturn(certificationRequestHolder);

        final PKCS10CertificationRequestHolder actualCertificationRequestHolder = certificateManagementServiceBean.generateCSR(certificateGenerationInfo);

        assertNotNull(actualCertificationRequestHolder);
        assertEquals(actualCertificationRequestHolder.getCertificateRequest().getSubject(), certificationRequestHolder.getCertificateRequest().getSubject());
    }

    private PKCS10CertificationRequest generatePKCS10Request(final List<GeneralName> generalNames) throws NoSuchAlgorithmException, SignatureException, IOException, InvalidKeyException,
            NoSuchProviderException, OperatorCreationException {

        final KeyPairGenerator kpg = KeyPairGenerator.getInstance(KEY_GEN_ALGORITHM);
        kpg.initialize(1024);
        final KeyPair kp = kpg.genKeyPair();

        final X500NameBuilder x500NameBld = new X500NameBuilder(BCStyle.INSTANCE);
        x500NameBld.addRDN(BCStyle.CN, ROOT_CA);
        final X500Name subject = x500NameBld.build();

        final PKCS10CertificationRequestBuilder requestBuilder = createPKCS10ReqBuilder(generalNames, kp, subject);
        return requestBuilder.build(new JcaContentSignerBuilder(SIGNATURE_ALGORITHM).setProvider(PROVIDER).build(kp.getPrivate()));
    }

    private PKCS10CertificationRequestBuilder createPKCS10ReqBuilder(final List<GeneralName> generalNames, final KeyPair kp, final X500Name subject) throws IOException {
        final PKCS10CertificationRequestBuilder requestBuilder = new JcaPKCS10CertificationRequestBuilder(subject, kp.getPublic());

        final ExtensionsGenerator extGen = new ExtensionsGenerator();
        extGen.addExtension(Extension.subjectAlternativeName, false, new GeneralNames(generalNames.toArray(new GeneralName[0])));
        requestBuilder.addAttribute(PKCSObjectIdentifiers.pkcs_9_at_extensionRequest, extGen.generate());
        return requestBuilder;
    }

    /**
     * Test method to check ImportCertificate.
     */
    @Test
    public void testImportCertificate() {
        final String caName = "caName";

        certificateManagementServiceBean.importCertificate(caName, x509Certificate);
        Mockito.verify(importCertificateManager).importCertificate(caName, x509Certificate);

    }

}
