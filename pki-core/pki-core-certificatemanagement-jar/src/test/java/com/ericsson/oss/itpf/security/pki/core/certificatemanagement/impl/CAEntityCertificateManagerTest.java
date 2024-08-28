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

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.kaps.api.KeyAccessProviderService;
import com.ericsson.oss.itpf.security.kaps.certificate.exception.CSRGenerationException;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.*;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.pki.common.certificatemanagement.builder.CSRBuilder;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateVersion;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.builder.ExtensionBuilder;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.BaseTest;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.persistence.handler.CertificateRequestPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.validator.AlgorithmValidator;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.validator.ImportCertificateCAValidator;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.eserviceproxy.KeyAccessProviderServiceProxy;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.KeyIdentifierModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.*;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.certificatefield.UnsupportedCertificateVersionException;

@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("PMD.UnusedPrivateField")
public class CAEntityCertificateManagerTest extends BaseTest {

    @InjectMocks
    private CAEntityCertificateManager cAEntityCertificateManager;

    @Mock
    private ExtensionBuilder extensionBuilder;

    @Mock
    private AlgorithmValidator algorithmValidator;

    @Mock
    private KeyPairGenerator keyPairGenerator;

    @Mock
    private CSRBuilder cSRBuilder;

    @Mock
    private CertificateRequestPersistenceHandler certificateRequestPersistenceHandler;

    @Spy
    KeyIdentifierModelMapper keyIdentifierModelMapper;

    @Mock
    KeyAccessProviderService keyAccessProviderServiceMock;

    @Mock
    ImportCertificatePersistenceHandler importCertificatePersistenceHandler;

    @Mock
    KeyPairPersistenceHandler keyPairPersistenceHandler;

    @Mock
    ImportCertificateCAValidator importCertificateCAValidator;

    @InjectMocks
    ImportCertificateManager importCertificateManager;

    @Mock
    KeyAccessProviderServiceProxy keyAccessProviderServiceProxy;

    private CertificateData certificateData;
    private KeyPair keyPair;
    private KeyIdentifier keyIdentifier;
    private PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder;
    private PKCS10CertificationRequest pkcs10CertificationRequest;
    private CertificateGenerationInfo certificateGenerationInfo;
    private CertificateAuthorityData certificateAuthorityData;
    private CertificateAuthorityData issuerData;
    private List<Extension> extensionList;
    private X509Certificate x509Certificate;
    private com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate certificateModel;
    private CertificateGenerationInfoData certificateGenerationInfoData;
    private KeyIdentifierData keyData;
    private PublicKey publicKey;
    final String caName = "caName";

    /**
     * Prepares initial data.
     * 
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeyException
     */
    @Before
    public void setUp() throws Exception {

        extensionList = new ArrayList<Extension>();
        certificateGenerationInfo = new CertificateGenerationInfo();
        final CertificateRequestData certificateRequestData = new CertificateRequestData();
        certificateAuthorityData = new CertificateAuthorityData();
        issuerData = new CertificateAuthorityData();
        certificateGenerationInfoData = new CertificateGenerationInfoData();
        keyData = new KeyIdentifierData();

        certificateModel = new com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate();

        certificateGenerationInfoData.setCertificateRequestData(certificateRequestData);
        final Algorithm signatureAlgorithm = prepareSignatureAlgorithm();
        certificateGenerationInfo.setSignatureAlgorithm(signatureAlgorithm);

        keyIdentifier = new KeyIdentifier();

        final Algorithm keyGenerationAlgorithm = prepareKeyGenerationAlgorithm();
        certificateGenerationInfo.setKeyGenerationAlgorithm(keyGenerationAlgorithm);

        GeneralName[] subjectAltName = new GeneralName[2];
        subjectAltName[0] = new GeneralName(GeneralName.dNSName, "abc.com");
        subjectAltName[1] = new GeneralName(GeneralName.directoryName, "CN=dir");

        pkcs10CertificationRequest = generatePKCS10Request(Arrays.asList(subjectAltName));
        pkcs10CertificationRequestHolder = new PKCS10CertificationRequestHolder(pkcs10CertificationRequest);

        final java.security.KeyPairGenerator gen = java.security.KeyPairGenerator.getInstance(KEY_GEN_ALGORITHM);
        gen.initialize(1024);
        keyPair = gen.generateKeyPair();
        publicKey = keyPair.getPublic();
        Mockito.when(keyAccessProviderServiceProxy.getKeyAccessProviderService()).thenReturn(keyAccessProviderServiceMock);
    }

    /**
     * Method to test generation of {@link Certificate} {@link CertificateGenerationInfo} for RootCA.
     *
     * @throws CertificateException
     * @throws CSRGenerationException
     * @throws IOException
     * @throws KeyAccessProviderServiceException
     * @throws KeyIdentifierNotFoundException
     */
    @Test
    public void testGenerateCertificateForRootCA() throws CertificateException, CSRGenerationException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException {

        setRootCAData();

        Mockito.doNothing().when(algorithmValidator).validateAlgorithm(certificateGenerationInfo.getKeyGenerationAlgorithm());
        Mockito.doNothing().when(algorithmValidator).validateAlgorithm(certificateGenerationInfo.getSignatureAlgorithm());

        Mockito.when(keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo)).thenReturn(keyData);

        Mockito.when(keyAccessProviderServiceMock.generateCSR(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.anyString(), Mockito.anyList())).thenReturn(
                pkcs10CertificationRequestHolder);

        Mockito.when(keyAccessProviderServiceMock.getPublicKey(keyIdentifier)).thenReturn(publicKey);

        Mockito.when(certGenInfoParser.getSubjectDNFromCertGenerationInfo(certificateGenerationInfo)).thenReturn(prepareSubject().toASN1String());

        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);

        Mockito.when(modelMapper.mapToCertificateGenerationInfoData(certificateGenerationInfo, pkcs10CertificationRequest.getEncoded(), certificateAuthorityData, null)).thenReturn(
                certificateGenerationInfoData);
        Mockito.when(
                certificateRequestPersistenceHandler.storeCertificateGenerationInfo(certificateGenerationInfo, pkcs10CertificationRequest.getEncoded(), certificateAuthorityData, null, certificateData))
                .thenReturn(certificateGenerationInfoData);

        Mockito.when(extensionBuilder.buildCertificateExtensions(certificateGenerationInfo, publicKey)).thenReturn(extensionList);

        Mockito.when(persistenceHelper.storeAndReturnCertificate(x509Certificate, certificateGenerationInfo, certificateAuthorityData, issuerData, keyData)).thenReturn(certificateData);

        Mockito.doNothing().when(persistenceHelper).updateCSR(certificateGenerationInfoData.getCertificateRequestData());

        Mockito.when(modelMapper.mapToCertificate(certificateData)).thenReturn(certificateModel);

        certificateModel = cAEntityCertificateManager.generateCertificate(certificateGenerationInfo);

        assertNotNull(certificateModel);
    }

    /**
     * Method to test generation of {@link Certificate} {@link CertificateGenerationInfo} for SubCA.
     *
     * @throws CertificateException
     * @throws CSRGenerationException
     * @throws IOException
     * @throws KeyAccessProviderServiceException
     * @throws KeyIdentifierNotFoundException
     */
    @Test
    public void testGenerateCertificateForSubCA() throws CertificateException, CSRGenerationException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException {

        setSubCAData(prepareCAData(false));

        Mockito.doNothing().when(algorithmValidator).validateAlgorithm(certificateGenerationInfo.getKeyGenerationAlgorithm());
        Mockito.doNothing().when(algorithmValidator).validateAlgorithm(certificateGenerationInfo.getSignatureAlgorithm());

        Mockito.when(keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo)).thenReturn(keyData);

        Mockito.when(certGenInfoParser.getSubjectDNFromCertGenerationInfo(certificateGenerationInfo)).thenReturn(prepareSubject().toASN1String());

        Mockito.when(keyAccessProviderServiceMock.generateCSR(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.anyString(), Mockito.anyList())).thenReturn(
                pkcs10CertificationRequestHolder);

        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);

        Mockito.when(modelMapper.mapToCertificateGenerationInfoData(certificateGenerationInfo, pkcs10CertificationRequest.getEncoded(), certificateAuthorityData, null)).thenReturn(
                certificateGenerationInfoData);
        Mockito.when(
                certificateRequestPersistenceHandler.storeCertificateGenerationInfo(certificateGenerationInfo, pkcs10CertificationRequest.getEncoded(), certificateAuthorityData, null, certificateData))
                .thenReturn(certificateGenerationInfoData);

        Mockito.when(extensionBuilder.buildCertificateExtensions(certificateGenerationInfo, keyPair.getPublic())).thenReturn(extensionList);

        Mockito.when(persistenceHelper.storeAndReturnCertificate(x509Certificate, certificateGenerationInfo, certificateAuthorityData, issuerData, keyData)).thenReturn(certificateData);

        Mockito.doNothing().when(persistenceHelper).updateCSR(certificateGenerationInfoData.getCertificateRequestData());
        Mockito.when(modelMapper.mapToCertificate(certificateData)).thenReturn(certificateModel);

        certificateModel = cAEntityCertificateManager.generateCertificate(certificateGenerationInfo);

        assertNotNull(certificateModel);
    }

    @Test(expected = com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException.class)
    public void testGenerateCertificate_InvalidCertificateException() throws CSRGenerationException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException {

        setRootCAData();
        setSubCAData(prepareCAData(false));

        Mockito.when(keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo)).thenReturn(keyData);

        Mockito.when(keyAccessProviderServiceMock.generateCSR(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.anyString(), Mockito.anyList())).thenReturn(
                pkcs10CertificationRequestHolder);

        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);

        Mockito.when(
                certificateRequestPersistenceHandler.storeCertificateGenerationInfo(certificateGenerationInfo, pkcs10CertificationRequest.getEncoded(), certificateAuthorityData, null, certificateData))
                .thenThrow(new InvalidCertificateException());

        certificateModel = cAEntityCertificateManager.generateCertificate(certificateGenerationInfo);

    }

    @Test(expected = com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException.class)
    public void testGenerateCertificate_InvalidCertificateExtensionsException() throws CSRGenerationException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException {

        setRootCAData();
        setSubCAData(prepareCAData(false));

        Mockito.when(keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo)).thenReturn(keyData);

        Mockito.when(keyAccessProviderServiceMock.generateCSR(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.anyString(), Mockito.anyList())).thenReturn(
                pkcs10CertificationRequestHolder);

        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);

        Mockito.when(
                certificateRequestPersistenceHandler.storeCertificateGenerationInfo(certificateGenerationInfo, pkcs10CertificationRequest.getEncoded(), certificateAuthorityData, null, certificateData))
                .thenThrow(new InvalidCertificateExtensionsException(""));

        certificateModel = cAEntityCertificateManager.generateCertificate(certificateGenerationInfo);

    }

    @Test(expected = com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException.class)
    public void testGenerateCertificate_KeyPairGenerationException() throws CSRGenerationException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException {

        setRootCAData();
        setSubCAData(prepareCAData(false));

        Mockito.when(keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo)).thenReturn(keyData);

        Mockito.when(keyAccessProviderServiceMock.generateCSR(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.anyString(), Mockito.anyList())).thenReturn(
                pkcs10CertificationRequestHolder);

        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);

        Mockito.when(
                certificateRequestPersistenceHandler.storeCertificateGenerationInfo(certificateGenerationInfo, pkcs10CertificationRequest.getEncoded(), certificateAuthorityData, null, certificateData))
                .thenThrow(new com.ericsson.oss.itpf.security.pki.core.exception.security.KeyPairGenerationException(""));

        certificateModel = cAEntityCertificateManager.generateCertificate(certificateGenerationInfo);

    }

    @Test(expected = com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException.class)
    public void testGenerateCertificate_UnsupportedCertificateVersionException() throws CSRGenerationException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException {

        setRootCAData();
        setSubCAData(prepareCAData(false));

        Mockito.when(keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo)).thenReturn(keyData);

        Mockito.when(keyAccessProviderServiceMock.generateCSR(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.anyString(), Mockito.anyList())).thenReturn(
                pkcs10CertificationRequestHolder);

        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);

        Mockito.when(
                certificateRequestPersistenceHandler.storeCertificateGenerationInfo(certificateGenerationInfo, pkcs10CertificationRequest.getEncoded(), certificateAuthorityData, null, certificateData))
                .thenThrow(new UnsupportedCertificateVersionException());

        certificateModel = cAEntityCertificateManager.generateCertificate(certificateGenerationInfo);

    }

    @Test(expected = com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException.class)
    public void testGenerateCertificateIOException() throws CSRGenerationException, IOException, KeyIdentifierNotFoundException, KeyAccessProviderServiceException {

        setRootCAData();
        setSubCAData(prepareCAData(false));

        Mockito.when(keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo)).thenReturn(keyData);

        Mockito.when(keyAccessProviderServiceMock.generateCSR(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.anyString(), Mockito.anyList())).thenReturn(
                pkcs10CertificationRequestHolder);

        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);

        Mockito.when(
                certificateRequestPersistenceHandler.storeCertificateGenerationInfo(certificateGenerationInfo, pkcs10CertificationRequest.getEncoded(), certificateAuthorityData, null, certificateData))
                .thenThrow(IOException.class);

        certificateModel = cAEntityCertificateManager.generateCertificate(certificateGenerationInfo);

    }

    @Test(expected = CertificateGenerationException.class)
    public void testGenerateCertificateKeyPairGenerationException() throws CertificateException, CSRGenerationException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException {

    setRootCAData();
    setSubCAData(prepareCAData(false));

    Mockito.when(keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo)).thenReturn(keyData);
    Mockito.when(keyAccessProviderServiceMock.generateCSR(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.anyString(), Mockito.anyList())).thenReturn(pkcs10CertificationRequestHolder);

    Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);
    Mockito.when(
            certificateRequestPersistenceHandler.storeCertificateGenerationInfo(certificateGenerationInfo, pkcs10CertificationRequest.getEncoded(), certificateAuthorityData, null, certificateData))
            .thenThrow(new com.ericsson.oss.itpf.security.pki.core.exception.security.KeyPairGenerationException(ErrorMessages.ERROR_GENERATING_KEY_PAIR));
    certificateModel = cAEntityCertificateManager.generateCertificate(certificateGenerationInfo);
}

    @Test(expected = com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException.class)
    public void testGenerateCertificateCertificateException() throws CSRGenerationException, IOException, KeyIdentifierNotFoundException, KeyAccessProviderServiceException {

        setRootCAData();
        setSubCAData(prepareCAData(false));

        Mockito.when(keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo)).thenReturn(keyData);

        Mockito.when(keyAccessProviderServiceMock.generateCSR(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.anyString(), Mockito.anyList())).thenReturn(
                pkcs10CertificationRequestHolder);

        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);

        Mockito.when(
                certificateRequestPersistenceHandler.storeCertificateGenerationInfo(certificateGenerationInfo, pkcs10CertificationRequest.getEncoded(), certificateAuthorityData, null, certificateData))
                .thenThrow(CertificateException.class);

        certificateModel = cAEntityCertificateManager.generateCertificate(certificateGenerationInfo);

    }

    @Test(expected = com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException.class)
    public void testGenerateCertificateKeyIdentifierNotFoundException() throws CSRGenerationException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException {

        setRootCAData();
        setSubCAData(prepareCAData(false));

        Mockito.when(keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo)).thenReturn(keyData);

        Mockito.when(keyAccessProviderServiceMock.generateCSR(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.anyString(), Mockito.anyList())).thenReturn(
                pkcs10CertificationRequestHolder);

        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);

        Mockito.when(
                certificateRequestPersistenceHandler.storeCertificateGenerationInfo(certificateGenerationInfo, pkcs10CertificationRequest.getEncoded(), certificateAuthorityData, null, certificateData))
                .thenThrow(KeyIdentifierNotFoundException.class);

        certificateModel = cAEntityCertificateManager.generateCertificate(certificateGenerationInfo);

    }

    @Test(expected = com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException.class)
    public void testGenerateCertificateCSRGenerationException() throws CSRGenerationException, IOException, KeyIdentifierNotFoundException, KeyAccessProviderServiceException {

        setRootCAData();
        setSubCAData(prepareCAData(false));

        Mockito.when(keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo)).thenReturn(keyData);

        Mockito.when(keyAccessProviderServiceMock.generateCSR(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.anyString(), Mockito.anyList())).thenReturn(pkcs10CertificationRequestHolder);

        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);

        Mockito.when(certificateRequestPersistenceHandler.storeCertificateGenerationInfo(certificateGenerationInfo, pkcs10CertificationRequest.getEncoded(), certificateAuthorityData, null, certificateData)).thenThrow(new CertificateGenerationException(ErrorMessages.UNABLE_TO_GENERATE_CSR_FOR_CA_FROM_KAPS));

        certificateModel = cAEntityCertificateManager.generateCertificate(certificateGenerationInfo);
    }

    /**
     * Method to test ImportCertificate
     */
    @Test
    public void testImportCertificate() {

        Mockito.doNothing().when(importCertificateCAValidator).validate(ROOT_CA);

        Mockito.doNothing().when(importCertificatePersistenceHandler).importCertificateForRootCA(ROOT_CA, x509Certificate);

        importCertificateManager.importCertificate(ROOT_CA, x509Certificate);

        Mockito.verify(importCertificateCAValidator).validate(ROOT_CA);

        Mockito.verify(importCertificatePersistenceHandler).importCertificateForRootCA(ROOT_CA, x509Certificate);
    }

    private void setRootCAData() {
        final CertificateAuthority certificateAuthority = prepareCAData(true);

        certificateGenerationInfo.setCAEntityInfo(certificateAuthority);
        certificateGenerationInfo.setIssuerCA(certificateAuthority);
        certificateGenerationInfo.setIssuerUniqueIdentifier(true);
        certificateGenerationInfo.setVersion(CertificateVersion.V3);
    }

    private void setSubCAData(final CertificateAuthority issuerCA) {
        final CertificateAuthority certAuthority = prepareCAData(true);

        certificateGenerationInfo.setCAEntityInfo(certAuthority);
        certificateGenerationInfo.setIssuerCA(issuerCA);
    }

    @Test(expected = CertificateServiceException.class)
    public void testGenerateCertificate_KeyAccessProviderServiceException() throws CertificateException, CSRGenerationException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException {

        setSubCAData(prepareCAData(false));

        Mockito.doNothing().when(algorithmValidator).validateAlgorithm(certificateGenerationInfo.getKeyGenerationAlgorithm());
        Mockito.doNothing().when(algorithmValidator).validateAlgorithm(certificateGenerationInfo.getSignatureAlgorithm());

        Mockito.when(keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo)).thenReturn(keyData);

        Mockito.when(certGenInfoParser.getSubjectDNFromCertGenerationInfo(certificateGenerationInfo)).thenReturn(prepareSubject().toASN1String());

        Mockito.when(keyAccessProviderServiceMock.generateCSR(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.anyString(), Mockito.anyList())).thenThrow(
                KeyAccessProviderServiceException.class);

        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);

        Mockito.when(modelMapper.mapToCertificateGenerationInfoData(certificateGenerationInfo, pkcs10CertificationRequest.getEncoded(), certificateAuthorityData, null)).thenReturn(
                certificateGenerationInfoData);
        Mockito.when(
                certificateRequestPersistenceHandler.storeCertificateGenerationInfo(certificateGenerationInfo, pkcs10CertificationRequest.getEncoded(), certificateAuthorityData, null, certificateData))
                .thenReturn(certificateGenerationInfoData);

        Mockito.when(extensionBuilder.buildCertificateExtensions(certificateGenerationInfo, keyPair.getPublic())).thenReturn(extensionList);

        Mockito.when(persistenceHelper.storeAndReturnCertificate(x509Certificate, certificateGenerationInfo, certificateAuthorityData, issuerData, keyData)).thenReturn(certificateData);

        Mockito.doNothing().when(persistenceHelper).updateCSR(certificateGenerationInfoData.getCertificateRequestData());
        Mockito.when(modelMapper.mapToCertificate(certificateData)).thenReturn(certificateModel);

        certificateModel = cAEntityCertificateManager.generateCertificate(certificateGenerationInfo);

    }
}
