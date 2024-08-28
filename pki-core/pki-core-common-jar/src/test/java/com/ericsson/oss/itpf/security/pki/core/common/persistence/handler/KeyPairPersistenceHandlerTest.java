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
package com.ericsson.oss.itpf.security.pki.core.common.persistence.handler;

import static org.junit.Assert.*;

import javax.inject.Inject;
import javax.persistence.EntityExistsException;
import javax.persistence.PersistenceException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.kaps.api.KeyAccessProviderService;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.kaps.exception.NotSupportedException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyIdentifierNotFoundException;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.kaps.model.KeyPairStatus;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.RequestType;
import com.ericsson.oss.itpf.security.pki.core.common.eserviceproxy.KeyAccessProviderServiceProxy;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.KeyIdentifierModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.KeyIdentifierData;
import com.ericsson.oss.itpf.security.pki.core.exception.security.KeyPairGenerationException;

@RunWith(MockitoJUnitRunner.class)
public class KeyPairPersistenceHandlerTest {

    @InjectMocks
    KeyPairPersistenceHandler keyPairPersistenceHandler;

    @Mock
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    KeyIdentifierModelMapper keyIdentifierModelMapper;

    @Mock
    KeyAccessProviderService keyAccessProviderService;

    @Mock
    KeyAccessProviderServiceProxy keyAccessProviderServiceProxy;

    @Mock
    Logger logger;

    @Mock
    private SystemRecorder systemRecorder;

    private static final String caName = "ENM_RootCA";
    private static final String keyIdentifier = "K000001";
    private static final String keyGenAlgName = "RSA";
    private static final int size = 2048;

    private KeyIdentifierData keyIdentifierData;
    private CertificateGenerationInfo certificateGenerationInfo;
    private KeyIdentifier keyIdentifierModel;

    @Before
    public void setUp() {

        keyIdentifierData = new KeyIdentifierData();
        keyIdentifierData.setKeyIdentifier(keyIdentifier);

        certificateGenerationInfo = new CertificateGenerationInfo();
        CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setName(caName);
        certificateGenerationInfo.setCAEntityInfo(certificateAuthority);

        final Algorithm keyGenAlg = new Algorithm();
        keyGenAlg.setName(keyGenAlgName);
        keyGenAlg.setKeySize(size);
        certificateGenerationInfo.setKeyGenerationAlgorithm(keyGenAlg);

        keyIdentifierModel = new KeyIdentifier();
        Mockito.when(keyAccessProviderServiceProxy.getKeyAccessProviderService()).thenReturn(keyAccessProviderService);

    }

    @Test
    public void testGetKeyIdentifierDataOfCA_RenewCase() {

        Mockito.when(certificatePersistenceHelper.getActiveKeyIdentifier(caName)).thenReturn(keyIdentifierData);
        certificateGenerationInfo.setRequestType(RequestType.RENEW);

        final KeyIdentifierData keyData = keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo);

        assertNotNull(keyData);
        assertEquals(keyIdentifierData.getKeyIdentifier(), keyData.getKeyIdentifier());
    }

    @Test
    public void testGetKeyIdentifierDataOfCA_ReKeyCase() throws KeyAccessProviderServiceException, KeyIdentifierNotFoundException, KeyPairGenerationException, com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyPairGenerationException, NotSupportedException {

        Mockito.when(certificatePersistenceHelper.getActiveKeyIdentifier(caName)).thenReturn(keyIdentifierData);
        Mockito.doNothing().when(certificatePersistenceHelper).updateKeyIdentifierStatus(keyIdentifierData, KeyPairStatus.INACTIVE);
        Mockito.when(keyIdentifierModelMapper.toModel(keyIdentifierData)).thenReturn(keyIdentifierModel);
        Mockito.doNothing().when(keyAccessProviderService).updateKeyPairStatus(keyIdentifierModel, KeyPairStatus.INACTIVE);

        Mockito.when(keyAccessProviderService.generateKeyPair("RSA", 2048)).thenReturn(keyIdentifierModel);
        Mockito.when(keyIdentifierModelMapper.fromModel(keyIdentifierModel, KeyPairStatus.ACTIVE)).thenReturn(keyIdentifierData);
        Mockito.when(certificatePersistenceHelper.storeAndReturnKeyData(keyIdentifierData)).thenReturn(keyIdentifierData);

        certificateGenerationInfo.setRequestType(RequestType.REKEY);

        final KeyIdentifierData keyData = keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo);

        assertNotNull(keyData);
        assertEquals(keyIdentifierData.getKeyIdentifier(), keyData.getKeyIdentifier());
    }

    @Test(expected = KeyPairGenerationException.class)
    public void testGetKeyIdentifierDataOfCA_ECDSAAlg() throws KeyAccessProviderServiceException, KeyIdentifierNotFoundException, NotSupportedException {

        Mockito.when(certificatePersistenceHelper.getActiveKeyIdentifier(caName)).thenReturn(keyIdentifierData);
        Mockito.doNothing().when(certificatePersistenceHelper).updateKeyIdentifierStatus(keyIdentifierData, KeyPairStatus.INACTIVE);
        Mockito.when(keyIdentifierModelMapper.toModel(keyIdentifierData)).thenReturn(keyIdentifierModel);
        Mockito.doNothing().when(keyAccessProviderService).updateKeyPairStatus(keyIdentifierModel, KeyPairStatus.INACTIVE);

        final Algorithm keyGenAlg = new Algorithm();
        keyGenAlg.setName("ECDSA");
        keyGenAlg.setKeySize(512);

        certificateGenerationInfo.setRequestType(RequestType.REKEY);
        certificateGenerationInfo.setKeyGenerationAlgorithm(keyGenAlg);

        keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo);

    }

    @Test(expected = KeyPairGenerationException.class)
    public void testGetKeyIdentifierDataOfCA_ECDSA_invalidKeySize() throws KeyAccessProviderServiceException, KeyIdentifierNotFoundException, NotSupportedException {

        Mockito.when(certificatePersistenceHelper.getActiveKeyIdentifier(caName)).thenReturn(keyIdentifierData);
        Mockito.doNothing().when(certificatePersistenceHelper).updateKeyIdentifierStatus(keyIdentifierData, KeyPairStatus.INACTIVE);
        Mockito.when(keyIdentifierModelMapper.toModel(keyIdentifierData)).thenReturn(keyIdentifierModel);
        Mockito.doNothing().when(keyAccessProviderService).updateKeyPairStatus(keyIdentifierModel, KeyPairStatus.INACTIVE);

        final Algorithm keyGenAlg = new Algorithm();
        keyGenAlg.setName("ECDSA");
        keyGenAlg.setKeySize(160);

        certificateGenerationInfo.setRequestType(RequestType.REKEY);
        certificateGenerationInfo.setKeyGenerationAlgorithm(keyGenAlg);

        keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo);

    }

    @Test(expected = KeyPairGenerationException.class)
    public void testgetKeyIdentifierDataOfCA_PersistenceException() throws KeyAccessProviderServiceException, KeyIdentifierNotFoundException, com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyPairGenerationException, NotSupportedException {

        Mockito.when(certificatePersistenceHelper.getActiveKeyIdentifier(caName)).thenReturn(keyIdentifierData);
        Mockito.doNothing().when(certificatePersistenceHelper).updateKeyIdentifierStatus(keyIdentifierData, KeyPairStatus.INACTIVE);
        Mockito.when(keyIdentifierModelMapper.toModel(keyIdentifierData)).thenReturn(keyIdentifierModel);
        Mockito.doNothing().when(keyAccessProviderService).updateKeyPairStatus(keyIdentifierModel, KeyPairStatus.INACTIVE);

        Mockito.when(keyAccessProviderService.generateKeyPair("RSA", 2048)).thenThrow(new PersistenceException());
        Mockito.when(keyIdentifierModelMapper.fromModel(keyIdentifierModel, KeyPairStatus.ACTIVE)).thenReturn(keyIdentifierData);
        Mockito.when(certificatePersistenceHelper.storeAndReturnKeyData(keyIdentifierData)).thenReturn(keyIdentifierData);

        certificateGenerationInfo.setRequestType(RequestType.REKEY);

        final KeyIdentifierData keyData = keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo);

    }

    @Test(expected = KeyPairGenerationException.class)
    public void testgetKeyIdentifierDataOfCA_NotSupportedException() throws KeyAccessProviderServiceException, KeyIdentifierNotFoundException, com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyPairGenerationException, NotSupportedException {

        Mockito.when(certificatePersistenceHelper.getActiveKeyIdentifier(caName)).thenReturn(keyIdentifierData);
        Mockito.doNothing().when(certificatePersistenceHelper).updateKeyIdentifierStatus(keyIdentifierData, KeyPairStatus.INACTIVE);
        Mockito.when(keyIdentifierModelMapper.toModel(keyIdentifierData)).thenReturn(keyIdentifierModel);
        Mockito.doNothing().when(keyAccessProviderService).updateKeyPairStatus(keyIdentifierModel, KeyPairStatus.INACTIVE);
        Mockito.when(keyAccessProviderService.generateKeyPair("RSA", 2048)).thenThrow(new KeyPairGenerationException("NotSupported"));
        Mockito.when(keyIdentifierModelMapper.fromModel(keyIdentifierModel, KeyPairStatus.ACTIVE)).thenReturn(keyIdentifierData);
        Mockito.when(certificatePersistenceHelper.storeAndReturnKeyData(keyIdentifierData)).thenReturn(keyIdentifierData);

        certificateGenerationInfo.setRequestType(RequestType.REKEY);

        final KeyIdentifierData keyData = keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo);

    }

    @Test(expected = KeyPairGenerationException.class)
    public void testgetKeyIdentifierDataOfCA_KeyAccessProviderServiceException() throws KeyAccessProviderServiceException, KeyIdentifierNotFoundException, com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyPairGenerationException, NotSupportedException {

        Mockito.when(certificatePersistenceHelper.getActiveKeyIdentifier(caName)).thenReturn(keyIdentifierData);
        Mockito.doNothing().when(certificatePersistenceHelper).updateKeyIdentifierStatus(keyIdentifierData, KeyPairStatus.INACTIVE);
        Mockito.when(keyIdentifierModelMapper.toModel(keyIdentifierData)).thenReturn(keyIdentifierModel);
        Mockito.doNothing().when(keyAccessProviderService).updateKeyPairStatus(keyIdentifierModel, KeyPairStatus.INACTIVE);

        Mockito.when(keyAccessProviderService.generateKeyPair("RSA", 2048)).thenThrow(new KeyAccessProviderServiceException("NotSupported"));
        Mockito.when(keyIdentifierModelMapper.fromModel(keyIdentifierModel, KeyPairStatus.ACTIVE)).thenReturn(keyIdentifierData);
        Mockito.when(certificatePersistenceHelper.storeAndReturnKeyData(keyIdentifierData)).thenReturn(keyIdentifierData);

        certificateGenerationInfo.setRequestType(RequestType.REKEY);

        final KeyIdentifierData keyData = keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo);

    }

    @Test(expected = KeyPairGenerationException.class)
    public void testgetKeyIdentifierDataOfCA_KeyIdentifierNotFoundException() throws KeyAccessProviderServiceException, KeyIdentifierNotFoundException, com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyPairGenerationException, NotSupportedException {

        Mockito.when(certificatePersistenceHelper.getActiveKeyIdentifier(caName)).thenReturn(keyIdentifierData);
        Mockito.doNothing().when(certificatePersistenceHelper).updateKeyIdentifierStatus(keyIdentifierData, KeyPairStatus.INACTIVE);
        Mockito.when(keyIdentifierModelMapper.toModel(keyIdentifierData)).thenReturn(keyIdentifierModel);
        Mockito.doNothing().when(keyAccessProviderService).updateKeyPairStatus(keyIdentifierModel, KeyPairStatus.INACTIVE);
        Mockito.when(keyAccessProviderService.generateKeyPair("RSA", 2048)).thenThrow(new KeyPairGenerationException("NotSupported"));
        Mockito.when(keyIdentifierModelMapper.fromModel(keyIdentifierModel, KeyPairStatus.ACTIVE)).thenReturn(keyIdentifierData);
        Mockito.when(certificatePersistenceHelper.storeAndReturnKeyData(keyIdentifierData)).thenReturn(keyIdentifierData);

        certificateGenerationInfo.setRequestType(RequestType.REKEY);

        final KeyIdentifierData keyData = keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo);

    }

    @Test(expected = KeyPairGenerationException.class)
    public void testgetKeyIdentifierDataOfCA_KeyPairGenerationException() throws KeyAccessProviderServiceException, KeyIdentifierNotFoundException, com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyPairGenerationException, NotSupportedException {

        Mockito.when(certificatePersistenceHelper.getActiveKeyIdentifier(caName)).thenReturn(keyIdentifierData);
        Mockito.doNothing().when(certificatePersistenceHelper).updateKeyIdentifierStatus(keyIdentifierData, KeyPairStatus.INACTIVE);
        Mockito.when(keyIdentifierModelMapper.toModel(keyIdentifierData)).thenReturn(keyIdentifierModel);
        Mockito.doNothing().when(keyAccessProviderService).updateKeyPairStatus(keyIdentifierModel, KeyPairStatus.INACTIVE);

        Mockito.when(keyAccessProviderService.generateKeyPair("RSA", 2048)).thenThrow(new KeyPairGenerationException("NotSupported"));
        Mockito.when(keyIdentifierModelMapper.fromModel(keyIdentifierModel, KeyPairStatus.ACTIVE)).thenReturn(keyIdentifierData);
        Mockito.when(certificatePersistenceHelper.storeAndReturnKeyData(keyIdentifierData)).thenReturn(keyIdentifierData);

        certificateGenerationInfo.setRequestType(RequestType.REKEY);

        final KeyIdentifierData keyData = keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo);

    }

    @Test(expected = KeyPairGenerationException.class)
    public void testgetKeyIdentifierDataOfCA_EntityExistsException() throws KeyAccessProviderServiceException, KeyIdentifierNotFoundException, com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyPairGenerationException, NotSupportedException {

        Mockito.when(certificatePersistenceHelper.getActiveKeyIdentifier(caName)).thenReturn(keyIdentifierData);
        Mockito.doNothing().when(certificatePersistenceHelper).updateKeyIdentifierStatus(keyIdentifierData, KeyPairStatus.INACTIVE);
        Mockito.when(keyIdentifierModelMapper.toModel(keyIdentifierData)).thenReturn(keyIdentifierModel);
        Mockito.doNothing().when(keyAccessProviderService).updateKeyPairStatus(keyIdentifierModel, KeyPairStatus.INACTIVE);

        Mockito.when(keyAccessProviderService.generateKeyPair("RSA", 2048)).thenThrow(new EntityExistsException("NotSupported"));
        Mockito.when(keyIdentifierModelMapper.fromModel(keyIdentifierModel, KeyPairStatus.ACTIVE)).thenReturn(keyIdentifierData);
        Mockito.when(certificatePersistenceHelper.storeAndReturnKeyData(keyIdentifierData)).thenReturn(keyIdentifierData);

        certificateGenerationInfo.setRequestType(RequestType.REKEY);

        final KeyIdentifierData keyData = keyPairPersistenceHandler.getKeyIdentifierDataOfCA(certificateGenerationInfo);

    }

    @Test
    public void testgetKeyIdentifierOfCA() throws KeyAccessProviderServiceException, KeyIdentifierNotFoundException, com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyPairGenerationException, NotSupportedException {

        Mockito.when(certificatePersistenceHelper.getActiveKeyIdentifier(caName)).thenReturn(keyIdentifierData);
        Mockito.doNothing().when(certificatePersistenceHelper).updateKeyIdentifierStatus(keyIdentifierData, KeyPairStatus.INACTIVE);
        Mockito.when(keyIdentifierModelMapper.toModel(keyIdentifierData)).thenReturn(keyIdentifierModel);
        Mockito.doNothing().when(keyAccessProviderService).updateKeyPairStatus(keyIdentifierModel, KeyPairStatus.INACTIVE);

        Mockito.when(keyAccessProviderService.generateKeyPair("RSA", 2048)).thenReturn(keyIdentifierModel);
        Mockito.when(keyIdentifierModelMapper.fromModel(keyIdentifierModel, KeyPairStatus.ACTIVE)).thenReturn(keyIdentifierData);
        Mockito.when(certificatePersistenceHelper.storeAndReturnKeyData(keyIdentifierData)).thenReturn(keyIdentifierData);

        certificateGenerationInfo.setRequestType(RequestType.REKEY);

        final KeyIdentifier keyData = keyPairPersistenceHandler.getKeyIdentifierOfCA(certificateGenerationInfo);

        assertNotNull(keyData);

    }
}
