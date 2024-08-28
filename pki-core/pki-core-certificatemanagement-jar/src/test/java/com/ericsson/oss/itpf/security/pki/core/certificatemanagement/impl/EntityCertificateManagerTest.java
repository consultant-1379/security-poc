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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.impl;

import static org.junit.Assert.assertNotNull;

import java.io.*;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.crmf.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.crmf.ProofOfPossessionSigningKeyBuilder;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.kaps.api.KeyAccessProviderService;
import com.ericsson.oss.itpf.security.kaps.certificate.exception.CSRGenerationException;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyIdentifierNotFoundException;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.*;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.builder.ExtensionBuilder;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.BaseTest;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.persistence.handler.CertificateRequestPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.validator.AlgorithmValidator;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;
import com.ericsson.oss.itpf.security.pki.core.exception.security.KeyPairGenerationException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.*;

@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("PMD.UnusedPrivateField")
public class EntityCertificateManagerTest extends BaseTest {

    @InjectMocks
    EntityCertificateManager entityCertificateManager;

    @Mock
    private ExtensionBuilder extensionBuilder;

    @Mock
    private AlgorithmValidator algorithmValidator;

    @Mock
    private CertificateRequestPersistenceHandler certificateRequestPersistenceHandlerBean;

    @Mock
    private X509Certificate x509Certificate;

    @Mock
    private Certificate certificateModel;

    @Mock
    private EntityInfo entityInfo;

    @Mock
    private KeyAccessProviderService keyAccessProviderServiceMock;

    private CertificateGenerationInfo certificateGenerationInfo;
    private CertificateGenerationInfoData certificateGenerationInfoData;
    private PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder;
    private KeyPair keyPair;
    private KeyIdentifier keyIdentifier;
    private PKCS10CertificationRequest certificationRequest;
    private EntityInfoData entityData;
    private CertificateData certificateData;
    private List<Extension> extensionList;
    private CertificateAuthorityData certificateAuthorityData;
    private CertificateAuthorityData issuerData;

    /**
     * Prepares initial data.
     * 
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeyException
     */
    @Before
    public void setUp() throws NoSuchAlgorithmException, IOException, InvalidKeyException {
        entityInfo = new EntityInfo();
        certificateGenerationInfo = new CertificateGenerationInfo();
        certificateGenerationInfoData = new CertificateGenerationInfoData();
        entityData = new EntityInfoData();
        extensionList = new ArrayList<Extension>();
        issuerData = new CertificateAuthorityData();
        certificateAuthorityData = new CertificateAuthorityData();

        final CertificateRequestData certificateRequestData = new CertificateRequestData();
        certificateGenerationInfoData.setCertificateRequestData(certificateRequestData);

        final Algorithm keyGenerationAlgorithm = prepareKeyGenerationAlgorithm();
        certificateGenerationInfo.setKeyGenerationAlgorithm(keyGenerationAlgorithm);

        keyPair = generateKeyPair(keyGenerationAlgorithm.getName(), keyGenerationAlgorithm.getKeySize());

        setEntityData();
        setIssuerCAData();

    }

    /**
     * Test method to generate Entity certificate with PKCS10Request.
     *
     * @throws CertificateException
     * @throws CSRGenerationException
     * @throws InvalidKeyException
     * @throws IOException
     * @throws KeyAccessProviderServiceException
     * @throws KeyIdentifierNotFoundException
     * @throws NoSuchAlgorithmException
     */
    @Test
    @Ignore
    public void testGenerateEntityCertificate_PKCS10() throws CertificateException, CSRGenerationException, InvalidKeyException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException, NoSuchAlgorithmException {

        final PKCS10CertificationRequest pkcs10CertificationRequest = setPKCSRequest();
        final Certificate certificateModel = generateEntitycertificate(pkcs10CertificationRequest.getEncoded());

        assertNotNull(certificateModel);
    }

    /**
     * 
     * Test method to generate Entity certificate with CRMFRequest.
     * 
     * @throws InvalidKeyException
     * @throws NoSuchAlgorithmException
     * @throws OperatorCreationException
     * @throws NoSuchProviderException
     * @throws IOException
     * @throws CertificateException
     */
    @Test
    public void testGenerateEntityCertificate_CRMF() throws InvalidKeyException, NoSuchAlgorithmException, OperatorCreationException, NoSuchProviderException, IOException, CertificateException {

        final CertificateRequestMessage certificateRequestMessage = setCRMFRequest();
        final Certificate certificateModel = generateEntitycertificate(certificateRequestMessage.getEncoded());
        assertNotNull(certificateModel);
    }

    @Test(expected = CertificateGenerationException.class)
    public void testGenerateEntityCertificate_CRMF_CertificateException() throws Exception {
        final CertificateRequestMessage certificateRequestMessage = setCRMFRequest();

        setEntityData();
        setIssuerCAData();

        Mockito.when(persistenceHelper.getEntityData(certificateGenerationInfo.getEntityInfo().getName())).thenReturn(entityData);
        Mockito.when(certificateRequestPersistenceHandlerBean.storeCertificateGenerationInfo(certificateGenerationInfo, certificateRequestMessage.getEncoded(), entityData, certificateData))
                .thenReturn(certificateGenerationInfoData);
        Mockito.when(modelMapper.mapToCertificate(certificateData)).thenThrow(CertificateException.class);
        entityCertificateManager.generateCertificate(certificateGenerationInfo);
    }

    @Test(expected = CertificateGenerationException.class)
    public void testGenerateEntityCertificate_CRMF_IOException() throws Exception {
        final CertificateRequestMessage certificateRequestMessage = setCRMFRequest();

        setEntityData();
        setIssuerCAData();

        Mockito.when(persistenceHelper.getEntityData(certificateGenerationInfo.getEntityInfo().getName())).thenReturn(entityData);
        Mockito.when(certificateRequestPersistenceHandlerBean.storeCertificateGenerationInfo(certificateGenerationInfo, certificateRequestMessage.getEncoded(), entityData, certificateData))
                .thenReturn(certificateGenerationInfoData);
        Mockito.when(modelMapper.mapToCertificate(certificateData)).thenThrow(IOException.class);
        entityCertificateManager.generateCertificate(certificateGenerationInfo);
    }

    @Test(expected = CertificateGenerationException.class)
    public void testGenerateEntityCertificate_InvalidCertificateException() throws Exception {
        final CertificateRequestMessage certificateRequestMessage = setCRMFRequest();

        setEntityData();
        setIssuerCAData();

        Mockito.when(persistenceHelper.getEntityData(certificateGenerationInfo.getEntityInfo().getName())).thenReturn(entityData);
        Mockito.when(certificateRequestPersistenceHandlerBean.storeCertificateGenerationInfo(certificateGenerationInfo, certificateRequestMessage.getEncoded(), entityData, certificateData))
                .thenThrow(new InvalidCertificateException());

        entityCertificateManager.generateCertificate(certificateGenerationInfo);
    }

    @Test(expected = CertificateGenerationException.class)
    public void testGenerateEntityCertificate_KeyPairGenerationException() throws Exception {
        final CertificateRequestMessage certificateRequestMessage = setCRMFRequest();

        setEntityData();
        setIssuerCAData();

        Mockito.when(persistenceHelper.getEntityData(certificateGenerationInfo.getEntityInfo().getName())).thenReturn(entityData);
        Mockito.when(certificateRequestPersistenceHandlerBean.storeCertificateGenerationInfo(certificateGenerationInfo, certificateRequestMessage.getEncoded(), entityData, certificateData))
                .thenThrow(new KeyPairGenerationException(""));

        entityCertificateManager.generateCertificate(certificateGenerationInfo);
    }

    @Test(expected = CertificateGenerationException.class)
    public void testGenerateEntityCertificate_InvalidCertificateExtensionsException() throws Exception {
        final CertificateRequestMessage certificateRequestMessage = setCRMFRequest();

        setEntityData();
        setIssuerCAData();

        Mockito.when(persistenceHelper.getEntityData(certificateGenerationInfo.getEntityInfo().getName())).thenReturn(entityData);
        Mockito.when(certificateRequestPersistenceHandlerBean.storeCertificateGenerationInfo(certificateGenerationInfo, certificateRequestMessage.getEncoded(), entityData, certificateData))
                .thenThrow(new InvalidCertificateExtensionsException(""));

        entityCertificateManager.generateCertificate(certificateGenerationInfo);
    }

    @Test(expected = CertificateGenerationException.class)
    public void testGenerateEntityCertificate_CRMF_NoSuchAlgorithmException() throws Exception {
        final CertificateRequestMessage certificateRequestMessage = setCRMFRequest();

        setEntityData();
        setIssuerCAData();

        Mockito.when(persistenceHelper.getEntityData(certificateGenerationInfo.getEntityInfo().getName())).thenReturn(entityData);
        Mockito.when(certificateRequestPersistenceHandlerBean.storeCertificateGenerationInfo(certificateGenerationInfo, certificateRequestMessage.getEncoded(), entityData, certificateData))
                .thenReturn(certificateGenerationInfoData);

        Mockito.when(modelMapper.mapToCertificate(certificateData)).thenThrow(IOException.class);
        entityCertificateManager.generateCertificate(certificateGenerationInfo);
    }

    private Certificate generateEntitycertificate(byte[] request) throws IOException, CertificateException {

        setEntityData();
        setIssuerCAData();

        Mockito.doNothing().when(algorithmValidator).validateAlgorithm(certificateGenerationInfo.getKeyGenerationAlgorithm());
        Mockito.doNothing().when(algorithmValidator).validateAlgorithm(certificateGenerationInfo.getSignatureAlgorithm());
        Mockito.when(persistenceHelper.getEntityData(certificateGenerationInfo.getEntityInfo().getName())).thenReturn(entityData);
        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getIssuerCA().getName())).thenReturn(issuerData);
        Mockito.when(certificateRequestPersistenceHandlerBean.storeCertificateGenerationInfo(certificateGenerationInfo, request, entityData, certificateData))
                .thenReturn(certificateGenerationInfoData);
        Mockito.when(extensionBuilder.buildCertificateExtensions(Matchers.any(CertificateGenerationInfo.class), Matchers.any(PublicKey.class))).thenReturn(extensionList);
        Mockito.when(certGenerator.generateCertificate(certificateGenerationInfo, keyIdentifier, keyPair.getPublic(), extensionList)).thenReturn(x509Certificate);
        Mockito.when(persistenceHelper.storeAndReturnCertificate(x509Certificate, certificateGenerationInfo, certificateAuthorityData, issuerData, null)).thenReturn(certificateData);
        Mockito.doNothing().when(persistenceHelper).updateCSR(certificateGenerationInfoData.getCertificateRequestData());
        Mockito.doNothing().when(persistenceHelper).updateEntityData(certificateData, entityData, issuerData, EntityStatus.ACTIVE);
        Mockito.when(modelMapper.mapToCertificate(certificateData)).thenReturn(certificateModel);
        certificateModel = entityCertificateManager.generateCertificate(certificateGenerationInfo);

        return certificateModel;
    }

    private CertificateRequestMessage setCRMFRequest() throws InvalidKeyException, NoSuchAlgorithmException, OperatorCreationException, NoSuchProviderException, IOException {

        final CertificateRequest csr = new CertificateRequest();
        final CertReqMsg certReqMsg = generateCRMF();
        final CertificateRequestMessage certificateRequestMessage = new CertificateRequestMessage(certReqMsg);
        final CRMFRequestHolder cRMFRequestHolder = new CRMFRequestHolder(certificateRequestMessage);
        csr.setCertificateRequestHolder(cRMFRequestHolder);
        certificateGenerationInfo.setCertificateRequest(csr);
        return certificateRequestMessage;
    }

    private CertReqMsg generateCRMF() throws NoSuchAlgorithmException, IOException, OperatorCreationException, InvalidKeyException, NoSuchProviderException {

        final CertTemplateBuilder ctBuilder = new CertTemplateBuilder();
        ctBuilder.setIssuer(new X500Name("CN=RootCA"));
        ctBuilder.setSubject(new X500Name("CN=SN98-stub-10.SoneraEricsson.com,OU=SoneraOuluEricsson,O=SoneraEricsson"));
        final GeneralNames subjectAltName = new GeneralNames(new GeneralName(1, "SN98-stub-10.SoneraEricsson.com"));
        final ByteArrayOutputStream bOut = new ByteArrayOutputStream();
		ASN1OutputStream.create(bOut, ASN1Encoding.DER).writeObject(subjectAltName);
        final byte[] value = bOut.toByteArray();

        final Extension extension = new Extension(Extension.subjectAlternativeName, true, value);
        final Extensions extn = new Extensions(extension);
        ctBuilder.setExtensions(extn);

        final KeyPair ownKeyPair = generateKeyPair("RSA", 2048);
        final byte[] bytes = ownKeyPair.getPublic().getEncoded();
        final ByteArrayInputStream bIn = new ByteArrayInputStream(bytes);
        final ASN1InputStream dIn = new ASN1InputStream(bIn);
        final SubjectPublicKeyInfo info = new SubjectPublicKeyInfo((ASN1Sequence) dIn.readObject());

        ctBuilder.setPublicKey(info);
        final int CERT_REQ_ID = 1;
        final CertRequest certRequest = new CertRequest(CERT_REQ_ID, ctBuilder.build(), null);

        final ProofOfPossessionSigningKeyBuilder poposkBuilder = new ProofOfPossessionSigningKeyBuilder(certRequest);
        final POPOSigningKey poposk = poposkBuilder.build(new JcaContentSignerBuilder("SHA1withRSA").setProvider("BC").build(ownKeyPair.getPrivate()));
        final ProofOfPossession popo = new ProofOfPossession(poposk);

        final CertReqMsg message = new CertReqMsg(certRequest, popo, null);
        dIn.close();

        return message;

    }

    private PKCS10CertificationRequest setPKCSRequest() throws CSRGenerationException, InvalidKeyException, IOException,  KeyAccessProviderServiceException, KeyIdentifierNotFoundException, NoSuchAlgorithmException {

        final Algorithm signatureAlgorithm = prepareSignatureAlgorithm();
        certificateGenerationInfo.setSignatureAlgorithm(signatureAlgorithm);
        final String subject = "CN=enmSecurity";
        certificationRequest = keyAccessProviderServiceMock.generateCSR(keyIdentifier, prepareSignatureAlgorithm().getName(), subject, null).getCertificateRequest();
        final PKCS10CertificationRequestHolder certificationRequestHolder = new PKCS10CertificationRequestHolder(certificationRequest);
        final CertificateRequest cSR = new CertificateRequest();
        cSR.setCertificateRequestHolder(certificationRequestHolder);
        certificateGenerationInfo.setCertificateRequest(cSR);
        return certificationRequest;

    }

    private void setEntityData() {
        final String entityName = "Entity1";
        entityInfo = new EntityInfo();
        entityInfo.setName(entityName);
        entityInfo.setSubject(prepareSubject());
        certificateGenerationInfo.setEntityInfo(entityInfo);
    }

    private void setIssuerCAData() {
        certificateGenerationInfo.setIssuerCA(prepareCAData(false));
    }
}
