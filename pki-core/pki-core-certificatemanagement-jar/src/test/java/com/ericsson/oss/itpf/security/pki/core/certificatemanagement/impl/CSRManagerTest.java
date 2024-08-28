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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.impl;

import java.io.IOException;
import java.security.*;
import java.util.*;

import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.x509.*;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.kaps.api.KeyAccessProviderService;
import com.ericsson.oss.itpf.security.kaps.certificate.exception.CSRGenerationException;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyIdentifierNotFoundException;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.RequestType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.builder.ExtensionBuilder;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.BaseTest;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.persistence.handler.CertificateRequestPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.validator.AlgorithmValidator;
import com.ericsson.oss.itpf.security.pki.core.common.eserviceproxy.KeyAccessProviderServiceProxy;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.KeyIdentifierModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.KeyPairPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.exception.configuration.AlgorithmValidationException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.KeyPairGenerationException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateExtensionsException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.CertificateRequestGenerationException;

@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("PMD.UnusedPrivateField")
public class CSRManagerTest extends BaseTest {

    @InjectMocks
    private CSRManager csrManager;

    @Mock
    private AlgorithmValidator algorithmValidator;

    @Mock
    private KeyAccessProviderService keyAccessProviderService;

    @Mock
    private ExtensionBuilder extensionBuilder;

    @Mock
    private CertificateRequestPersistenceHandler certificateRequestPersistenceHandler;

    @Mock
    private KeyPairPersistenceHandler keyPairPersistenceHandler;

    @Mock
    private KeyIdentifierModelMapper keyIdentifierModelMapper;

    @Mock
    KeyAccessProviderServiceProxy keyAccessProviderServiceProxy;

    private CertificateGenerationInfo certificateGenerationInfo;
    private CertificateAuthorityData certificateAuthorityData;
    private Algorithm keyGenerationAlgorithm;
    private Algorithm signatureAlgorithm;
    private KeyIdentifierData keyIdentifierData;
    private KeyIdentifier keyIdentifier;
    private PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder;
    private PKCS10CertificationRequest certificationRequest;
    private List<Extension> cSRExtensions;
    private PublicKey publicKey;

    @Before
    public void setUp() throws InvalidKeyException, IOException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, SignatureException {

        keyGenerationAlgorithm = prepareKeyGenerationAlgorithm();
        signatureAlgorithm = prepareSignatureAlgorithm();

        certificateGenerationInfo = new CertificateGenerationInfo();
        certificateGenerationInfo.setKeyGenerationAlgorithm(keyGenerationAlgorithm);
        certificateGenerationInfo.setSignatureAlgorithm(signatureAlgorithm);
        certificateGenerationInfo.setCAEntityInfo(prepareCAData(true));

        certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setSubjectDN(prepareSubject().toASN1String());
        keyIdentifierData = prepareKeyIdentifierData();
        keyIdentifier = new KeyIdentifier();

        GeneralName[] subjectAltName = new GeneralName[2];
        subjectAltName[0] = new GeneralName(GeneralName.dNSName, "abc.com");
        subjectAltName[1] = new GeneralName(GeneralName.directoryName, "CN=dir");
        certificationRequest = generatePKCS10Request(Arrays.asList(subjectAltName));

        pkcs10CertificationRequestHolder = new PKCS10CertificationRequestHolder(certificationRequest);

        cSRExtensions = buildCSRExtensions();
        publicKey = generateKeyPair(keyGenerationAlgorithm.getName(), keyGenerationAlgorithm.getKeySize()).getPublic();
        Mockito.when(keyAccessProviderServiceProxy.getKeyAccessProviderService()).thenReturn(keyAccessProviderService);
    }

    @Test
    public void testExportCSR_WithNewKey() throws CSRGenerationException, InvalidKeyException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException,  NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, SignatureException {

        certificateGenerationInfo.setRequestType(RequestType.REKEY);
        Mockito.doNothing().when(algorithmValidator).validateAlgorithm(keyGenerationAlgorithm);
        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);
        Mockito.when(keyPairPersistenceHandler.getKeyIdentifierOfCA(certificateGenerationInfo)).thenReturn(keyIdentifier);
        Mockito.when(keyAccessProviderService.getPublicKey(keyIdentifier)).thenReturn(publicKey);
        Mockito.when(extensionBuilder.buildCertificateExtensions(certificateGenerationInfo, publicKey)).thenReturn(cSRExtensions);
        Mockito.when(keyAccessProviderService.generateCSR(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.anyString(), Mockito.anyList())).thenReturn(pkcs10CertificationRequestHolder);
        Mockito.when(certificateRequestPersistenceHandler.storeCertificateGenerationInfo(certificateGenerationInfo, pkcs10CertificationRequestHolder.getCertificateRequest().getEncoded(), certificateAuthorityData, null, null)).thenReturn(new CertificateGenerationInfoData());

        csrManager.generateCSR(certificateGenerationInfo);
    }

    @Test(expected = CertificateRequestGenerationException.class)
    public void testExportCSR_WithNewKey_IOExceptionFromKaps() throws CSRGenerationException, InvalidKeyException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException,  NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, SignatureException {

        certificateGenerationInfo.setRequestType(RequestType.REKEY);

        Mockito.doNothing().when(algorithmValidator).validateAlgorithm(keyGenerationAlgorithm);
        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);
        Mockito.when(keyPairPersistenceHandler.getKeyIdentifierOfCA(certificateGenerationInfo)).thenReturn(keyIdentifier);
        Mockito.when(keyAccessProviderService.getPublicKey(keyIdentifier)).thenReturn(publicKey);
        Mockito.when(extensionBuilder.buildCertificateExtensions(certificateGenerationInfo, publicKey)).thenReturn(cSRExtensions);
        Mockito.when(keyAccessProviderService.generateCSR(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.anyString(), Mockito.anyList())).thenThrow(IOException.class);

        csrManager.generateCSR(certificateGenerationInfo);
    }

    @Test(expected = CertificateRequestGenerationException.class)
    public void testExportCSR_WithNewKey_CSRGenerationException_fromKaps() throws CSRGenerationException, InvalidKeyException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException,  NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, SignatureException {

        certificateGenerationInfo.setRequestType(RequestType.REKEY);

        Mockito.doNothing().when(algorithmValidator).validateAlgorithm(keyGenerationAlgorithm);
        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);
        Mockito.when(keyPairPersistenceHandler.getKeyIdentifierOfCA(certificateGenerationInfo)).thenReturn(keyIdentifier);
        Mockito.when(keyAccessProviderService.getPublicKey(keyIdentifier)).thenReturn(publicKey);
        Mockito.when(extensionBuilder.buildCertificateExtensions(certificateGenerationInfo, publicKey)).thenReturn(cSRExtensions);
        Mockito.when(keyAccessProviderService.generateCSR(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.anyString(), Mockito.anyList())).thenThrow(
                new CSRGenerationException("CSR generation failed"));

        csrManager.generateCSR(certificateGenerationInfo);
    }

    @Test(expected = CertificateRequestGenerationException.class)
    public void testExportCSR_WithNewKey_KeyIdentifierNotFoundException() throws CSRGenerationException, InvalidKeyException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException,  NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, SignatureException {

        certificateGenerationInfo.setRequestType(RequestType.REKEY);

        Mockito.doNothing().when(algorithmValidator).validateAlgorithm(keyGenerationAlgorithm);
        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);
        Mockito.when(keyPairPersistenceHandler.getKeyIdentifierOfCA(certificateGenerationInfo)).thenReturn(keyIdentifier);
        Mockito.when(keyAccessProviderService.getPublicKey(keyIdentifier)).thenReturn(publicKey);
        Mockito.when(extensionBuilder.buildCertificateExtensions(certificateGenerationInfo, publicKey)).thenReturn(cSRExtensions);
        Mockito.when(keyAccessProviderService.generateCSR(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.anyString(), Mockito.anyList())).thenThrow(
                new KeyIdentifierNotFoundException("Key not found"));

        csrManager.generateCSR(certificateGenerationInfo);
    }

    @Test(expected = CertificateServiceException.class)
    public void testExportCSR_WithNewKey_KeyAccessProviderServiceException() throws CSRGenerationException, InvalidKeyException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException,  NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, SignatureException {

        certificateGenerationInfo.setRequestType(RequestType.REKEY);

        Mockito.doNothing().when(algorithmValidator).validateAlgorithm(keyGenerationAlgorithm);
        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);
        Mockito.when(keyPairPersistenceHandler.getKeyIdentifierOfCA(certificateGenerationInfo)).thenReturn(keyIdentifier);
        Mockito.when(keyAccessProviderService.getPublicKey(keyIdentifier)).thenReturn(publicKey);
        Mockito.when(extensionBuilder.buildCertificateExtensions(certificateGenerationInfo, publicKey)).thenReturn(cSRExtensions);
        Mockito.when(keyAccessProviderService.generateCSR(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.anyString(), Mockito.anyList())).thenThrow(
                new KeyAccessProviderServiceException("Key not found"));

        csrManager.generateCSR(certificateGenerationInfo);
    }

    @Test(expected = CertificateRequestGenerationException.class)
    public void testExportCSR_WithNewKey_KeyPairGenerationException() throws CSRGenerationException, InvalidKeyException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException,  NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, SignatureException {

        certificateGenerationInfo.setRequestType(RequestType.REKEY);

        Mockito.doNothing().when(algorithmValidator).validateAlgorithm(keyGenerationAlgorithm);
        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);
        Mockito.when(keyPairPersistenceHandler.getKeyIdentifierOfCA(certificateGenerationInfo)).thenThrow(new KeyPairGenerationException("key pair not generated"));

        csrManager.generateCSR(certificateGenerationInfo);
    }

    @Test(expected = CertificateRequestGenerationException.class)
    public void testExportCSR_WithNewKey_AlgorithmValidationException() throws InvalidKeyException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, SignatureException {

        certificateGenerationInfo.setRequestType(RequestType.REKEY);

        Mockito.doThrow(new AlgorithmValidationException("algorithm not found ")).when(algorithmValidator).validateAlgorithm(keyGenerationAlgorithm);

        csrManager.generateCSR(certificateGenerationInfo);
    }

    @Test(expected = CertificateRequestGenerationException.class)
    public void testExportCSR_WithNewKey_InvalidCertificateExtensionsException() throws InvalidKeyException, IOException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, SignatureException {

        certificateGenerationInfo.setRequestType(RequestType.REKEY);

        Mockito.doNothing().when(algorithmValidator).validateAlgorithm(keyGenerationAlgorithm);
        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);
        Mockito.when(keyPairPersistenceHandler.getKeyIdentifierOfCA(certificateGenerationInfo)).thenReturn(keyIdentifier);
        Mockito.when(keyAccessProviderService.getPublicKey(keyIdentifier)).thenReturn(publicKey);
        Mockito.when(extensionBuilder.buildCertificateExtensions(certificateGenerationInfo, publicKey)).thenThrow(new InvalidCertificateExtensionsException("extensions build failed"));

        csrManager.generateCSR(certificateGenerationInfo);
    }

    @Test
    public void testExportCSR_WithOldKey() throws CSRGenerationException, InvalidKeyException, IOException, KeyIdentifierNotFoundException, KeyAccessProviderServiceException, NoSuchAlgorithmException, NoSuchProviderException, OperatorCreationException, SignatureException {

        certificateGenerationInfo.setRequestType(RequestType.RENEW);

        Mockito.doNothing().when(algorithmValidator).validateAlgorithm(keyGenerationAlgorithm);
        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);
        Mockito.when(keyPairPersistenceHandler.getKeyIdentifierOfCA(certificateGenerationInfo)).thenReturn(keyIdentifier);
        Mockito.when(keyAccessProviderService.getPublicKey(keyIdentifier)).thenReturn(publicKey);
        Mockito.when(extensionBuilder.buildCertificateExtensions(certificateGenerationInfo, publicKey)).thenReturn(cSRExtensions);
        Mockito.when(keyAccessProviderService.generateCSR(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.anyString(), Mockito.anyList())).thenReturn(pkcs10CertificationRequestHolder);
        Mockito.when(
                certificateRequestPersistenceHandler.storeCertificateGenerationInfo(certificateGenerationInfo, pkcs10CertificationRequestHolder.getCertificateRequest().getEncoded(),
                        certificateAuthorityData, null, null)).thenReturn(new CertificateGenerationInfoData());

        csrManager.generateCSR(certificateGenerationInfo);
    }

    @Test(expected = CertificateRequestGenerationException.class)
    public void testExportCSR_WithNewKey_CertificateRequestGenerationException() throws CSRGenerationException, KeyAccessProviderServiceException, KeyIdentifierNotFoundException {

        certificateGenerationInfo.setRequestType(RequestType.REKEY);

        Mockito.doNothing().when(algorithmValidator).validateAlgorithm(keyGenerationAlgorithm);
        Mockito.when(persistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName())).thenReturn(certificateAuthorityData);
        Mockito.when(keyPairPersistenceHandler.getKeyIdentifierOfCA(certificateGenerationInfo)).thenReturn(keyIdentifier);
        Mockito.when(keyAccessProviderService.getPublicKey(keyIdentifier)).thenReturn(publicKey);
        Mockito.when(extensionBuilder.buildCertificateExtensions(certificateGenerationInfo, publicKey)).thenReturn(cSRExtensions);
        Mockito.when(keyAccessProviderService.generateCSR(Mockito.any(KeyIdentifier.class), Mockito.anyString(), Mockito.anyString(), Mockito.anyList())).thenThrow(CertificateRequestGenerationException.class);

        csrManager.generateCSR(certificateGenerationInfo);
    }

    private List<Extension> buildCSRExtensions() throws IOException {

        final List<Extension> cSRExtensions = new ArrayList<Extension>();

        final BasicConstraints basicConstraints = prepareBasicConstraints_BouncyCastle();
        final Extension basicConstraintsExtension = new Extension(Extension.basicConstraints, false, new DEROctetString(basicConstraints));

        final KeyUsage keyUsage = prepareKeyUsage_BouncyCastle();
        final Extension keyUsageExtension = new Extension(Extension.keyUsage, false, new DEROctetString(keyUsage));

        cSRExtensions.add(basicConstraintsExtension);
        cSRExtensions.add(keyUsageExtension);

        return cSRExtensions;

    }
}
