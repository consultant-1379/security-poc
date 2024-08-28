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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper;

import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.resources.Resource;
import com.ericsson.oss.itpf.sdk.resources.Resources;
import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.CACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.EntityCertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SubjectSetUPData;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.PKIManagerEServiceProxy;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.util.KeyStoreUtil;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.*;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;
import com.ericsson.oss.itpf.security.pki.manager.rest.common.KeyStoreHelper;
import com.ericsson.oss.itpf.security.pki.manager.rest.util.ErrorMessages;

@RunWith(PowerMockRunner.class)
@PrepareForTest(Resources.class)
public class EntityCertificateOperationsHelperTest {

    @InjectMocks
    com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.EntityCertificateOperationsHelper entityCertificateOperationsHelper;

    @Spy
    Logger logger = LoggerFactory.getLogger(EntityCertificateOperationsHelper.class);

    @Mock
    CACertificateManagementService caCertificateManagementService;

    @Mock
    EntityCertificateManagementService entityCertificateManagementService;

    @Mock
    KeyStoreUtil keyStoreUtil;

    @Mock
    Resource resource;

    @Mock
    KeyStoreHelper keyStoreHelper;

    @Mock
    PKIManagerEServiceProxy pkiManagerEServiceProxy;

    SubjectSetUPData subjectSetUpData;

    Certificate certificate;

    List<Certificate> certificates = null;

    List<CertificateChain> certificateChains = null;

    CertificateChain certificateChain;

    private SetUPData setUPData;

    @Before
    public void setUp() throws Exception {

        setUPData = new SetUPData();

        certificates = setUPData.getCAEntityCertificateChain();
        certificateChain = new CertificateChain();
        certificateChain.setCertificateChain(certificates);
        certificateChains = new ArrayList<CertificateChain>();
        certificateChains.add(certificateChain);
        Mockito.when(pkiManagerEServiceProxy.getCaCertificateManagementService()).thenReturn(caCertificateManagementService);
        Mockito.when(pkiManagerEServiceProxy.getEntityCertificateManagementService()).thenReturn(entityCertificateManagementService);
    }

    @Test
    public void testIssueCertificateForRootCA_withOutChain() throws Exception {

        final CertificateRequestDTO certificateRequestDTO = setUPData.getRootCACertificateRequestDTOWithOutChain();

        final KeyStoreInfo keyStoreInfo = getKeyStroeInfo(certificateRequestDTO);
        PowerMockito.when(keyStoreHelper.createKeyStoreInfo(certificateRequestDTO.getName(), certificateRequestDTO.getFormat(), certificateRequestDTO.getPassword(), certificateRequestDTO.getName()))
                .thenReturn(keyStoreInfo);

        PowerMockito.mockStatic(Resources.class);
        PowerMockito.when(keyStoreHelper.createKeyStore(keyStoreInfo, certificates)).thenReturn("ARJ_Root-35c35df3596fc0e6-1450954693459.jks");

        entityCertificateOperationsHelper.issueCertificateForCA(certificateRequestDTO);
    }

    @Test
    public void testIssueCertificateForRootCA_withChain() throws Exception {

        final CertificateRequestDTO certificateRequestDTO = setUPData.getRootCACertificateRequestDTOWithChain();

        Mockito.when(caCertificateManagementService.getCertificateChainList(certificateRequestDTO.getName(), CertificateStatus.ACTIVE)).thenReturn(certificateChains);

        final KeyStoreInfo keyStoreInfo = getKeyStroeInfo(certificateRequestDTO);
        PowerMockito.when(keyStoreHelper.createKeyStoreInfo(certificateRequestDTO.getName(), certificateRequestDTO.getFormat(), certificateRequestDTO.getPassword(), certificateRequestDTO.getName()))
                .thenReturn(keyStoreInfo);

        PowerMockito.mockStatic(Resources.class);
        PowerMockito.when(keyStoreHelper.createKeyStore(keyStoreInfo, certificates)).thenReturn("ARJ_Root-35c35df3596fc0e6-1450954693459.jks");

        entityCertificateOperationsHelper.issueCertificateForCA(certificateRequestDTO);
    }

    @Test
    public void testIssueCertificateForEntity_withOutChain() throws Exception {

        final CertificateRequestDTO certificateRequestDTO = setUPData.getEndEntityCertificateRequestDTOWithOutChain();
        final String password = certificateRequestDTO.getPassword();

        com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfo = null;
        final char[] keyStorePassword = { 'e', 'n', 't', 'i', 't', 'y' };
        keyStoreInfo = mockKeyStore(keyStorePassword, SetUPData.ENTITY_NAME);

        final KeyStoreInfo keyStoreInfoCommon = getKeyStroeInfo(certificateRequestDTO);
        PowerMockito.when(keyStoreHelper.createKeyStoreInfo(certificateRequestDTO.getName(), certificateRequestDTO.getFormat(), certificateRequestDTO.getPassword(), certificateRequestDTO.getName()))
                .thenReturn(keyStoreInfoCommon);
        PowerMockito.when(entityCertificateManagementService.generateCertificate(certificateRequestDTO.getName(), password.toCharArray(), mappingCommonToApiType(certificateRequestDTO.getFormat())))
                .thenReturn(keyStoreInfo);

        PowerMockito.mockStatic(Resources.class);

        PowerMockito.when(entityCertificateManagementService.getCertificateChain(certificateRequestDTO.getName())).thenReturn(certificateChain);
        PowerMockito.when(keyStoreHelper.buildKeyStoreWithCertificateChain(keyStoreInfo, certificateRequestDTO, certificateChain)).thenReturn("ARJ_Root-35c35df3596fc0e6-1450954693459.jks");

        entityCertificateOperationsHelper.issueCertificateForEntity(certificateRequestDTO);
    }

    @Test
    public void testIssueCertificateForEntity_withChain() throws Exception {

        final CertificateRequestDTO certificateRequestDTO = setUPData.getEndEntityCertificateRequestDTOWithChain();

        final String password = certificateRequestDTO.getPassword();

        com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfo = null;
        final char[] keyStorePassword = { 'e', 'n', 't', 'i', 't', 'y' };
        keyStoreInfo = mockKeyStore(keyStorePassword, SetUPData.ENTITY_NAME);

        PowerMockito.when(entityCertificateManagementService.generateCertificate(certificateRequestDTO.getName(), password.toCharArray(), mappingCommonToApiType(certificateRequestDTO.getFormat())))
                .thenReturn(keyStoreInfo);

        PowerMockito.mockStatic(Resources.class);

        PowerMockito.when(entityCertificateManagementService.getCertificateChain(certificateRequestDTO.getName())).thenReturn(certificateChain);
        PowerMockito.when(keyStoreHelper.buildKeyStoreWithCertificateChain(keyStoreInfo, certificateRequestDTO, certificateChain)).thenReturn("ARJ_Root-35c35df3596fc0e6-1450954693459.jks");

        entityCertificateOperationsHelper.issueCertificateForEntity(certificateRequestDTO);
    }

    @Test
    public void testIssueCertificateForEntity_withOutPassword() throws Exception {

        final CertificateRequestDTO certificateRequestDTO = setUPData.getEndEntityCertificateRequestDTOWithOutPassword();

        Mockito.when(caCertificateManagementService.getCertificateChainList(certificateRequestDTO.getName(), CertificateStatus.ACTIVE)).thenReturn(certificateChains);

        entityCertificateOperationsHelper.issueCertificateForEntity(certificateRequestDTO);
    }

    @Test
    public void testEntityCertificateChain() throws Exception {

        final KeyStoreFileDTO keyStoreFileDTO = setUPData.getKeyStoreFileDTO();

        Mockito.when(entityCertificateManagementService.getCertificateChain(keyStoreFileDTO.getName())).thenReturn(certificateChain);

        entityCertificateOperationsHelper.getEntityCertificateChain(keyStoreFileDTO.getName(), keyStoreFileDTO.isChain(), certificate);
    }

    @Test
    public void testEntityCertificateChainFalse() throws Exception {

        final KeyStoreFileDTO keyStoreFileDTO = setUPData.getFileDTOWithOutChain();

        Mockito.when(entityCertificateManagementService.getCertificateChain(keyStoreFileDTO.getName())).thenReturn(certificateChain);

        entityCertificateOperationsHelper.getEntityCertificateChain(keyStoreFileDTO.getName(), keyStoreFileDTO.isChain(), certificate);
    }

    @Test
    public void testRekeyCertificateForEndEntityWithChain() throws Exception {

        final CertificateRequestDTO certificateRequestDTO = setUPData.getEndEntityCertificateRequestDTOWithChain();
        final String password = "";

        com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfo = null;
        final char[] keyStorePassword = { 'e', 'n', 't', 'i', 't', 'y' };
        keyStoreInfo = mockKeyStore(keyStorePassword, SetUPData.ENTITY_NAME);

        final KeyStoreInfo keyStoreInfoCommon = getKeyStroeInfo(certificateRequestDTO);
        PowerMockito.when(keyStoreHelper.createKeyStoreInfo(certificateRequestDTO.getName(), certificateRequestDTO.getFormat(), certificateRequestDTO.getPassword(), certificateRequestDTO.getName()))
                .thenReturn(keyStoreInfoCommon);
        PowerMockito.when(entityCertificateManagementService.reKeyCertificate(certificateRequestDTO.getName(), password.toCharArray(), mappingCommonToApiType(certificateRequestDTO.getFormat())))
                .thenReturn(keyStoreInfo);

        PowerMockito.mockStatic(Resources.class);

        PowerMockito.when(entityCertificateManagementService.getCertificateChain(certificateRequestDTO.getName())).thenReturn(certificateChain);
        PowerMockito.when(keyStoreHelper.buildKeyStoreWithCertificateChain(keyStoreInfo, certificateRequestDTO, certificateChain)).thenReturn("ARJ_Root-35c35df3596fc0e6-1450954693459.jks");

        entityCertificateOperationsHelper.rekeyCertificateForEndEntity(certificateRequestDTO);
    }

    @Test
    public void testRekeyCertificateForEndEntityWithOutChain() throws Exception {

        final CertificateRequestDTO certificateRequestDTO = setUPData.getEndEntityCertificateRequestDTOWithOutChain();
        final String password = certificateRequestDTO.getPassword();

        com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfo = null;

        final char[] keyStorePassword = { 'e', 'n', 't', 'i', 't', 'y' };
        keyStoreInfo = mockKeyStore(keyStorePassword, SetUPData.ENTITY_NAME);

        final KeyStoreInfo keyStoreInfoCommon = getKeyStroeInfo(certificateRequestDTO);
        PowerMockito.when(keyStoreHelper.createKeyStoreInfo(certificateRequestDTO.getName(), certificateRequestDTO.getFormat(), certificateRequestDTO.getPassword(), certificateRequestDTO.getName()))
                .thenReturn(keyStoreInfoCommon);
        PowerMockito.when(entityCertificateManagementService.reKeyCertificate(certificateRequestDTO.getName(), password.toCharArray(), mappingCommonToApiType(certificateRequestDTO.getFormat())))
                .thenReturn(keyStoreInfo);

        PowerMockito.mockStatic(Resources.class);

        PowerMockito.when(entityCertificateManagementService.getCertificateChain(certificateRequestDTO.getName())).thenReturn(certificateChain);
        PowerMockito.when(keyStoreHelper.buildKeyStoreWithCertificateChain(keyStoreInfo, certificateRequestDTO, certificateChain)).thenReturn("ARJ_Root-35c35df3596fc0e6-1450954693459.jks");

        entityCertificateOperationsHelper.rekeyCertificateForEndEntity(certificateRequestDTO);
    }

    @Test
    public void testRekeyEndEntityCertificate() throws Exception {

        final EntityReissueDTO entityReissueDTO = setUPData.getEntityReissueDTO();
        final String password = entityReissueDTO.getPassword();

        com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfo = null;

        final char[] keyStorePassword = { 'e', 'n', 't', 'i', 't', 'y' };
        keyStoreInfo = mockKeyStore(keyStorePassword, SetUPData.ENTITY_NAME);

        PowerMockito.when(entityCertificateManagementService.reKeyCertificate(entityReissueDTO.getName(), password.toCharArray(), mappingCommonToApiType(entityReissueDTO.getFormat()))).thenReturn(
                keyStoreInfo);
        PowerMockito.mockStatic(Resources.class);

        PowerMockito.when(entityCertificateManagementService.getCertificateChain(entityReissueDTO.getName())).thenReturn(certificateChain);
        PowerMockito.when(keyStoreHelper.buildKeyStoreWithCertificateChain(keyStoreInfo, setUPData.getEndEntityCertificateRequestDTOWithChain(), certificateChain)).thenReturn(
                "ARJ_Root-35c35df3596fc0e6-1450954693459.jks");

        entityCertificateOperationsHelper.rekeyEndEntityCertificate(entityReissueDTO);
    }

    private KeyStoreInfo getKeyStroeInfo(final CertificateRequestDTO certificateRequestDTO) {

        final KeyStoreInfo keyStoreInfo = new KeyStoreInfo();
        keyStoreInfo.setAliasName(certificateRequestDTO.getName());
        keyStoreInfo.setFilePath("certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.jks");
        keyStoreInfo.setKeyStoreType(certificateRequestDTO.getFormat());
        keyStoreInfo.setPassword(certificateRequestDTO.getPassword());
        return keyStoreInfo;
    }

    private com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType mappingCommonToApiType(final KeyStoreType keyStoreType) {

        switch (keyStoreType) {
        case JKS:
            return com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType.JKS;
        case PKCS12:
            return com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType.PKCS12;
        case PEM:
            return com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType.PEM;
        default:
            throw new IllegalArgumentException(ErrorMessages.FORMAT_NOT_SUPPORTED);
        }

    }

    private com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo mockKeyStore(final char[] password, final String alias) {

        Mockito.when(
                keyStoreUtil.createKeyStore(new char[] { Mockito.anyChar() }, Mockito.any(com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType.class),
                        Mockito.any(KeyPair.class), Mockito.any(X509Certificate[].class), Mockito.anyString())).thenReturn("mykeystore.jks");

        final byte[] keyStoreFileData = "entity".getBytes();

        final com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo expectedKeyStoreInfo = buildKeyStoreInfoModel(SetUPData.ENTITY_NAME, password, keyStoreFileData);
        Mockito.when(keyStoreUtil.buildKeyStoreInfoModel(new char[] { Mockito.anyChar() }, Mockito.anyString(), new byte[] { Mockito.anyByte() })).thenReturn(expectedKeyStoreInfo);

        return expectedKeyStoreInfo;
    }

    private com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo buildKeyStoreInfoModel(final String alias, final char[] password, final byte[] keyStoreContent) {

        final com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfo = new com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo();
        keyStoreInfo.setPassword(password);
        keyStoreInfo.setAlias(alias);
        keyStoreInfo.setKeyStoreFileData(keyStoreContent);

        return keyStoreInfo;
    }
}
