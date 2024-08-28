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
package com.ericsson.oss.itpf.security.pki.manager.rest.common;

import static org.junit.Assert.assertEquals;

import java.io.FileNotFoundException;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.powermock.api.mockito.PowerMockito;
import org.powermock.core.classloader.annotations.PrepareForTest;
import org.powermock.modules.junit4.PowerMockRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.resources.Resource;
import com.ericsson.oss.itpf.sdk.resources.Resources;
import com.ericsson.oss.itpf.security.pki.common.keystore.*;
import com.ericsson.oss.itpf.security.pki.common.keystore.exception.KeyStoreTypeNotSupportedException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.util.FileUtility;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.entitymanagement.dto.CertificateRequestDTO;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;

@RunWith(PowerMockRunner.class)
@PrepareForTest(Resources.class)
public class KeyStoreHelperTest {

    @InjectMocks
    KeyStoreHelper KeyStoreHelper;

    @Mock
    KeyStoreFileWriterHelper keyStoreFileWriterHelper;

    @Mock
    CertificateKeyStoreFileBuilder certificateKeyStoreFileBuilder;

    @Mock
    JksPkcs12KeyStoreFileWriter jksPkcs12KeyStoreFileWriter;

    @Mock
    KeyStoreFileWriterFactory keyStoreFileWriterFactory;

    @Mock
    Resource resource;

    @Mock
    FileUtility fileUtility;

    @Mock
    Logger logger;

    SetUPData setUPData;

    private String fileName = "ARJ_Root-35c35df3596fc0e6-1450954693459";
    private String filePath = "src/test/resources/certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.jks";
    private String password = "entity";
    private String aliasName = "ARJ_Root";

    /**
     * Method for setting up test data.
     */
    @Before
    public void setUp() throws Exception {
        setUPData = new SetUPData();
        PowerMockito.mockStatic(Resources.class);
        PowerMockito.when(Resources.getFileSystemResource(Mockito.anyString())).thenReturn(resource);
    }

    @Test
    public void testCreateKeyStoreInfo() {

        PowerMockito.when(keyStoreFileWriterHelper.getTempFile(fileName, KeyStoreType.JKS.value())).thenReturn(filePath);

        KeyStoreInfo keyStoreInfo = KeyStoreHelper.createKeyStoreInfo(fileName, KeyStoreType.JKS, password, aliasName);

        assertEquals(filePath, keyStoreInfo.getFilePath());
        assertEquals(KeyStoreType.JKS, keyStoreInfo.getKeyStoreType());
        assertEquals(password, keyStoreInfo.getPassword());
        assertEquals(aliasName, keyStoreInfo.getAliasName());

    }

    @Test
    public void testCreateKeyStore() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException {

        final List<Certificate> certList = getCertificatesForDownload();
        final KeyStoreInfo keyStoreInfo = getKeyStoreInfo();

        PowerMockito.mockStatic(Resources.class);
        PowerMockito.when(keyStoreFileWriterFactory.getKeystoreFileWriterInstance(keyStoreInfo)).thenReturn(jksPkcs12KeyStoreFileWriter);
        PowerMockito.when(jksPkcs12KeyStoreFileWriter.createCertKeyStore(Matchers.anyList(), Matchers.any(KeyStoreInfo.class))).thenReturn("certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.jks");

        KeyStoreHelper.createKeyStore(keyStoreInfo, certList);

    }

    @Test(expected = CertificateServiceException.class)
    public void testCreateKeyStore_CertificateException() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException {

        final List<Certificate> certList = getCertificatesForDownload();
        final KeyStoreInfo keyStoreInfo = getKeyStoreInfo();

        PowerMockito.mockStatic(Resources.class);
        PowerMockito.when(keyStoreFileWriterFactory.getKeystoreFileWriterInstance(keyStoreInfo)).thenReturn(jksPkcs12KeyStoreFileWriter);
        PowerMockito.when(jksPkcs12KeyStoreFileWriter.createCertKeyStore(Matchers.anyList(), Matchers.any(KeyStoreInfo.class))).thenThrow(new CertificateException());

        KeyStoreHelper.createKeyStore(keyStoreInfo, certList);

    }

    @Test(expected = CertificateServiceException.class)
    public void testCreateKeyStore_FileNotFoundException() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException {

        final List<Certificate> certList = getCertificatesForDownload();
        final KeyStoreInfo keyStoreInfo = getKeyStoreInfo();

        PowerMockito.mockStatic(Resources.class);
        PowerMockito.when(keyStoreFileWriterFactory.getKeystoreFileWriterInstance(keyStoreInfo)).thenReturn(jksPkcs12KeyStoreFileWriter);
        PowerMockito.when(jksPkcs12KeyStoreFileWriter.createCertKeyStore(Matchers.anyList(), Matchers.any(KeyStoreInfo.class))).thenThrow(new FileNotFoundException());

        KeyStoreHelper.createKeyStore(keyStoreInfo, certList);

    }

    @Test(expected = CertificateServiceException.class)
    public void testCreateKeyStore_IOException() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException {

        final List<Certificate> certList = getCertificatesForDownload();
        final KeyStoreInfo keyStoreInfo = getKeyStoreInfo();

        PowerMockito.mockStatic(Resources.class);
        PowerMockito.when(keyStoreFileWriterFactory.getKeystoreFileWriterInstance(keyStoreInfo)).thenReturn(jksPkcs12KeyStoreFileWriter);
        PowerMockito.when(jksPkcs12KeyStoreFileWriter.createCertKeyStore(Matchers.anyList(), Matchers.any(KeyStoreInfo.class))).thenThrow(new IOException());

        KeyStoreHelper.createKeyStore(keyStoreInfo, certList);

    }

    @Test(expected = CertificateServiceException.class)
    public void testCreateKeyStore_KeyStoreException() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException {

        final List<Certificate> certList = getCertificatesForDownload();
        final KeyStoreInfo keyStoreInfo = getKeyStoreInfo();

        PowerMockito.mockStatic(Resources.class);
        PowerMockito.when(keyStoreFileWriterFactory.getKeystoreFileWriterInstance(keyStoreInfo)).thenReturn(jksPkcs12KeyStoreFileWriter);
        PowerMockito.when(jksPkcs12KeyStoreFileWriter.createCertKeyStore(Matchers.anyList(), Matchers.any(KeyStoreInfo.class))).thenThrow(new KeyStoreException());

        KeyStoreHelper.createKeyStore(keyStoreInfo, certList);

    }

    @Test(expected = CertificateServiceException.class)
    public void testCreateKeyStore_NoSuchAlgorithmException() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException {

        final List<Certificate> certList = getCertificatesForDownload();
        final KeyStoreInfo keyStoreInfo = getKeyStoreInfo();

        PowerMockito.mockStatic(Resources.class);
        PowerMockito.when(keyStoreFileWriterFactory.getKeystoreFileWriterInstance(keyStoreInfo)).thenReturn(jksPkcs12KeyStoreFileWriter);
        PowerMockito.when(jksPkcs12KeyStoreFileWriter.createCertKeyStore(Matchers.anyList(), Matchers.any(KeyStoreInfo.class))).thenThrow(new NoSuchAlgorithmException());

        KeyStoreHelper.createKeyStore(keyStoreInfo, certList);

    }

    @Test(expected = CertificateServiceException.class)
    public void testCreateKeyStore_NoSuchProviderException() throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException {

        final List<Certificate> certList = getCertificatesForDownload();
        final KeyStoreInfo keyStoreInfo = getKeyStoreInfo();

        PowerMockito.mockStatic(Resources.class);
        PowerMockito.when(keyStoreFileWriterFactory.getKeystoreFileWriterInstance(keyStoreInfo)).thenReturn(jksPkcs12KeyStoreFileWriter);
        PowerMockito.when(jksPkcs12KeyStoreFileWriter.createCertKeyStore(Matchers.anyList(), Matchers.any(KeyStoreInfo.class))).thenThrow(new NoSuchProviderException());

        KeyStoreHelper.createKeyStore(keyStoreInfo, certList);

    }

    @Test
    public void testLoadAndStoreKeyStore() throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException {

        final byte[] keyStoreFileData = "entity".getBytes();
        final char[] keyStorePassword = { 'e', 'n', 't', 'i', 't', 'y' };
        final KeyStoreInfo keyStoreInfo = getKeyStoreInfo();
        final com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfoData = buildKeyStoreInfoModel(SetUPData.ENTITY_NAME, keyStorePassword,
                keyStoreFileData);
        KeyStore keyStore = initializeKeyStore(keyStoreInfo);
        PowerMockito.when(keyStoreFileWriterHelper.loadKeyStoreWithData(keyStoreInfo, keyStoreInfoData.getKeyStoreFileData())).thenReturn(keyStore);

        KeyStoreHelper.loadAndStoreKeyStore(password, keyStoreInfo, keyStoreInfoData);
    }

    @Test(expected = CertificateServiceException.class)
    public void testLoadAndStoreKeyStore_CertificateException() throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException {
        final byte[] keyStoreFileData = "entity".getBytes();
        final char[] keyStorePassword = { 'e', 'n', 't', 'i', 't', 'y' };
        final KeyStoreInfo keyStoreInfo = getKeyStoreInfo();
        final com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfoData = buildKeyStoreInfoModel(SetUPData.ENTITY_NAME, keyStorePassword,
                keyStoreFileData);
        KeyStore keyStore = initializeKeyStore(keyStoreInfo);
        PowerMockito.when(keyStoreFileWriterHelper.loadKeyStoreWithData(Matchers.any(KeyStoreInfo.class), Matchers.any(byte[].class))).thenThrow(new CertificateException());
        KeyStoreHelper.loadAndStoreKeyStore(password, keyStoreInfo, keyStoreInfoData);
    }

    @Test(expected = CertificateServiceException.class)
    public void testLoadAndStoreKeyStore_FileNotFoundException() throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException {
        final byte[] keyStoreFileData = "entity".getBytes();
        final char[] keyStorePassword = { 'e', 'n', 't', 'i', 't', 'y' };
        final KeyStoreInfo keyStoreInfo = getKeyStoreInfo();
        final com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfoData = buildKeyStoreInfoModel(SetUPData.ENTITY_NAME, keyStorePassword,
                keyStoreFileData);
        KeyStore keyStore = initializeKeyStore(keyStoreInfo);
        PowerMockito.when(keyStoreFileWriterHelper.loadKeyStoreWithData(Matchers.any(KeyStoreInfo.class), Matchers.any(byte[].class))).thenThrow(new FileNotFoundException());
        KeyStoreHelper.loadAndStoreKeyStore(password, keyStoreInfo, keyStoreInfoData);
    }

    @Test(expected = CertificateServiceException.class)
    public void testLoadAndStoreKeyStore_IOException() throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException {
        final byte[] keyStoreFileData = "entity".getBytes();
        final char[] keyStorePassword = { 'e', 'n', 't', 'i', 't', 'y' };
        final KeyStoreInfo keyStoreInfo = getKeyStoreInfo();
        final com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfoData = buildKeyStoreInfoModel(SetUPData.ENTITY_NAME, keyStorePassword,
                keyStoreFileData);
        KeyStore keyStore = initializeKeyStore(keyStoreInfo);
        PowerMockito.when(keyStoreFileWriterHelper.loadKeyStoreWithData(Matchers.any(KeyStoreInfo.class), Matchers.any(byte[].class))).thenThrow(new IOException());
        KeyStoreHelper.loadAndStoreKeyStore(password, keyStoreInfo, keyStoreInfoData);
    }

    @Test(expected = CertificateServiceException.class)
    public void testLoadAndStoreKeyStore_KeyStoreException() throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException {
        final byte[] keyStoreFileData = "entity".getBytes();
        final char[] keyStorePassword = { 'e', 'n', 't', 'i', 't', 'y' };
        final KeyStoreInfo keyStoreInfo = getKeyStoreInfo();
        final com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfoData = buildKeyStoreInfoModel(SetUPData.ENTITY_NAME, keyStorePassword,
                keyStoreFileData);
        KeyStore keyStore = initializeKeyStore(keyStoreInfo);
        PowerMockito.when(keyStoreFileWriterHelper.loadKeyStoreWithData(Matchers.any(KeyStoreInfo.class), Matchers.any(byte[].class))).thenThrow(new KeyStoreException());
        KeyStoreHelper.loadAndStoreKeyStore(password, keyStoreInfo, keyStoreInfoData);
    }

    @Test(expected = CertificateServiceException.class)
    public void testLoadAndStoreKeyStore_NoSuchAlgorithmException() throws CertificateException, KeyStoreException, NoSuchAlgorithmException, IOException {
        final byte[] keyStoreFileData = "entity".getBytes();
        final char[] keyStorePassword = { 'e', 'n', 't', 'i', 't', 'y' };
        final KeyStoreInfo keyStoreInfo = getKeyStoreInfo();
        final com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfoData = buildKeyStoreInfoModel(SetUPData.ENTITY_NAME, keyStorePassword,
                keyStoreFileData);
        KeyStore keyStore = initializeKeyStore(keyStoreInfo);
        PowerMockito.when(keyStoreFileWriterHelper.loadKeyStoreWithData(Matchers.any(KeyStoreInfo.class), Matchers.any(byte[].class))).thenThrow(new NoSuchAlgorithmException());
        KeyStoreHelper.loadAndStoreKeyStore(password, keyStoreInfo, keyStoreInfoData);
    }

    @Test
    public void testBuildKeyStoreWithCertificateChain() throws CertificateException, IOException, UnrecoverableKeyException, KeyStoreTypeNotSupportedException, KeyStoreException,
            NoSuchAlgorithmException, NoSuchProviderException {

        final CertificateRequestDTO certificateRequestDTO = setUPData.getRootCACertificateRequestDTOWithChain();

        final CertificateChain certificateChain = new CertificateChain();
        certificateChain.setCertificateChain(setUPData.getEntityCertificateChain("certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.cer"));

        final byte[] keyStoreFileData = "entity".getBytes();
        final char[] keyStorePassword = { 'e', 'n', 't', 'i', 't', 'y' };
        final com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfo = buildKeyStoreInfoModel(SetUPData.ENTITY_NAME, keyStorePassword, keyStoreFileData);

        Mockito.when(keyStoreFileWriterHelper.getTempFile(fileName, com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType.JKS.value())).thenReturn(filePath);
        PowerMockito.mockStatic(Resources.class);
        Mockito.when(keyStoreFileWriterFactory.getKeystoreFileWriterInstance(Mockito.any(KeyStoreInfo.class))).thenReturn(jksPkcs12KeyStoreFileWriter);
        Mockito.when(jksPkcs12KeyStoreFileWriter.addCertChainToKeyStore(Mockito.anyListOf(Certificate.class), Mockito.any(KeyStoreInfo.class), Mockito.any(byte[].class))).thenReturn(
                "certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.cer");

        KeyStoreHelper.buildKeyStoreWithCertificateChain(keyStoreInfo, certificateRequestDTO, certificateChain);
    }

    @Test(expected = CertificateServiceException.class)
    public void testBuildKeyStoreWithCertificateChain_CertificateException() throws CertificateException, IOException, UnrecoverableKeyException, KeyStoreTypeNotSupportedException, KeyStoreException,
            NoSuchAlgorithmException, NoSuchProviderException {

        final CertificateRequestDTO certificateRequestDTO = setUPData.getRootCACertificateRequestDTOWithChain();

        final CertificateChain certificateChain = new CertificateChain();
        certificateChain.setCertificateChain(setUPData.getEntityCertificateChain("certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.cer"));

        final byte[] keyStoreFileData = "entity".getBytes();
        final char[] keyStorePassword = { 'e', 'n', 't', 'i', 't', 'y' };
        final com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfo = buildKeyStoreInfoModel(SetUPData.ENTITY_NAME, keyStorePassword, keyStoreFileData);

        Mockito.when(keyStoreFileWriterHelper.getTempFile(fileName, com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType.JKS.value())).thenReturn(filePath);
        PowerMockito.mockStatic(Resources.class);
        Mockito.when(keyStoreFileWriterFactory.getKeystoreFileWriterInstance(Mockito.any(KeyStoreInfo.class))).thenReturn(jksPkcs12KeyStoreFileWriter);
        PowerMockito.when(jksPkcs12KeyStoreFileWriter.addCertChainToKeyStore(Mockito.anyListOf(Certificate.class), Mockito.any(KeyStoreInfo.class), Mockito.any(byte[].class))).thenThrow(
                new CertificateException());

        KeyStoreHelper.buildKeyStoreWithCertificateChain(keyStoreInfo, certificateRequestDTO, certificateChain);
    }

    @Test(expected = CertificateServiceException.class)
    public void testBuildKeyStoreWithCertificateChain_IOException() throws CertificateException, IOException, UnrecoverableKeyException, KeyStoreTypeNotSupportedException, KeyStoreException,
            NoSuchAlgorithmException, NoSuchProviderException {

        final CertificateRequestDTO certificateRequestDTO = setUPData.getRootCACertificateRequestDTOWithChain();

        final CertificateChain certificateChain = new CertificateChain();
        certificateChain.setCertificateChain(setUPData.getEntityCertificateChain("certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.cer"));

        final byte[] keyStoreFileData = "entity".getBytes();
        final char[] keyStorePassword = { 'e', 'n', 't', 'i', 't', 'y' };
        final com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfo = buildKeyStoreInfoModel(SetUPData.ENTITY_NAME, keyStorePassword, keyStoreFileData);

        Mockito.when(keyStoreFileWriterHelper.getTempFile(fileName, com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType.JKS.value())).thenReturn(filePath);
        PowerMockito.mockStatic(Resources.class);
        Mockito.when(keyStoreFileWriterFactory.getKeystoreFileWriterInstance(Mockito.any(KeyStoreInfo.class))).thenReturn(jksPkcs12KeyStoreFileWriter);
        PowerMockito.when(jksPkcs12KeyStoreFileWriter.addCertChainToKeyStore(Mockito.anyListOf(Certificate.class), Mockito.any(KeyStoreInfo.class), Mockito.any(byte[].class))).thenThrow(
                new IOException());

        KeyStoreHelper.buildKeyStoreWithCertificateChain(keyStoreInfo, certificateRequestDTO, certificateChain);
    }

    @Test(expected = CertificateServiceException.class)
    public void testBuildKeyStoreWithCertificateChain_KeyStoreException() throws CertificateException, IOException, UnrecoverableKeyException, KeyStoreTypeNotSupportedException, KeyStoreException,
            NoSuchAlgorithmException, NoSuchProviderException {

        final CertificateRequestDTO certificateRequestDTO = setUPData.getRootCACertificateRequestDTOWithChain();

        final CertificateChain certificateChain = new CertificateChain();
        certificateChain.setCertificateChain(setUPData.getEntityCertificateChain("certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.cer"));

        final byte[] keyStoreFileData = "entity".getBytes();
        final char[] keyStorePassword = { 'e', 'n', 't', 'i', 't', 'y' };
        final com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfo = buildKeyStoreInfoModel(SetUPData.ENTITY_NAME, keyStorePassword, keyStoreFileData);

        Mockito.when(keyStoreFileWriterHelper.getTempFile(fileName, com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType.JKS.value())).thenReturn(filePath);
        PowerMockito.mockStatic(Resources.class);
        Mockito.when(keyStoreFileWriterFactory.getKeystoreFileWriterInstance(Mockito.any(KeyStoreInfo.class))).thenReturn(jksPkcs12KeyStoreFileWriter);
        PowerMockito.when(jksPkcs12KeyStoreFileWriter.addCertChainToKeyStore(Mockito.anyListOf(Certificate.class), Mockito.any(KeyStoreInfo.class), Mockito.any(byte[].class))).thenThrow(
                new KeyStoreException());

        KeyStoreHelper.buildKeyStoreWithCertificateChain(keyStoreInfo, certificateRequestDTO, certificateChain);
    }

    @Test(expected = CertificateServiceException.class)
    public void testBuildKeyStoreWithCertificateChain_NoSuchAlgorithmException() throws CertificateException, IOException, UnrecoverableKeyException, KeyStoreTypeNotSupportedException,
            KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException {

        final CertificateRequestDTO certificateRequestDTO = setUPData.getRootCACertificateRequestDTOWithChain();

        final CertificateChain certificateChain = new CertificateChain();
        certificateChain.setCertificateChain(setUPData.getEntityCertificateChain("certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.cer"));

        final byte[] keyStoreFileData = "entity".getBytes();
        final char[] keyStorePassword = { 'e', 'n', 't', 'i', 't', 'y' };
        final com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfo = buildKeyStoreInfoModel(SetUPData.ENTITY_NAME, keyStorePassword, keyStoreFileData);

        Mockito.when(keyStoreFileWriterHelper.getTempFile(fileName, com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType.JKS.value())).thenReturn(filePath);
        PowerMockito.mockStatic(Resources.class);
        Mockito.when(keyStoreFileWriterFactory.getKeystoreFileWriterInstance(Mockito.any(KeyStoreInfo.class))).thenReturn(jksPkcs12KeyStoreFileWriter);
        PowerMockito.when(jksPkcs12KeyStoreFileWriter.addCertChainToKeyStore(Mockito.anyListOf(Certificate.class), Mockito.any(KeyStoreInfo.class), Mockito.any(byte[].class))).thenThrow(
                new NoSuchAlgorithmException());

        KeyStoreHelper.buildKeyStoreWithCertificateChain(keyStoreInfo, certificateRequestDTO, certificateChain);
    }

    @Test(expected = CertificateServiceException.class)
    public void testBuildKeyStoreWithCertificateChain__NoSuchProviderException() throws CertificateException, IOException, UnrecoverableKeyException, KeyStoreTypeNotSupportedException,
            KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException {

        final CertificateRequestDTO certificateRequestDTO = setUPData.getRootCACertificateRequestDTOWithChain();

        final CertificateChain certificateChain = new CertificateChain();
        certificateChain.setCertificateChain(setUPData.getEntityCertificateChain("certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.cer"));

        final byte[] keyStoreFileData = "entity".getBytes();
        final char[] keyStorePassword = { 'e', 'n', 't', 'i', 't', 'y' };
        final com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfo = buildKeyStoreInfoModel(SetUPData.ENTITY_NAME, keyStorePassword, keyStoreFileData);

        Mockito.when(keyStoreFileWriterHelper.getTempFile(fileName, com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType.JKS.value())).thenReturn(filePath);
        PowerMockito.mockStatic(Resources.class);
        Mockito.when(keyStoreFileWriterFactory.getKeystoreFileWriterInstance(Mockito.any(KeyStoreInfo.class))).thenReturn(jksPkcs12KeyStoreFileWriter);
        PowerMockito.when(jksPkcs12KeyStoreFileWriter.addCertChainToKeyStore(Mockito.anyListOf(Certificate.class), Mockito.any(KeyStoreInfo.class), Mockito.any(byte[].class))).thenThrow(
                new NoSuchProviderException());

        KeyStoreHelper.buildKeyStoreWithCertificateChain(keyStoreInfo, certificateRequestDTO, certificateChain);
    }

    @Test(expected = CertificateServiceException.class)
    public void testBuildKeyStoreWithCertificateChain_UnrecoverableKeyException() throws CertificateException, IOException, UnrecoverableKeyException, KeyStoreTypeNotSupportedException,
            KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException {

        final CertificateRequestDTO certificateRequestDTO = setUPData.getRootCACertificateRequestDTOWithChain();

        final CertificateChain certificateChain = new CertificateChain();
        certificateChain.setCertificateChain(setUPData.getEntityCertificateChain("certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.cer"));

        final byte[] keyStoreFileData = "entity".getBytes();
        final char[] keyStorePassword = { 'e', 'n', 't', 'i', 't', 'y' };
        final com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfo = buildKeyStoreInfoModel(SetUPData.ENTITY_NAME, keyStorePassword, keyStoreFileData);

        Mockito.when(keyStoreFileWriterHelper.getTempFile(fileName, com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType.JKS.value())).thenReturn(filePath);
        PowerMockito.mockStatic(Resources.class);
        Mockito.when(keyStoreFileWriterFactory.getKeystoreFileWriterInstance(Mockito.any(KeyStoreInfo.class))).thenReturn(jksPkcs12KeyStoreFileWriter);
        PowerMockito.when(jksPkcs12KeyStoreFileWriter.addCertChainToKeyStore(Mockito.anyListOf(Certificate.class), Mockito.any(KeyStoreInfo.class), Mockito.any(byte[].class))).thenThrow(
                new UnrecoverableKeyException());

        KeyStoreHelper.buildKeyStoreWithCertificateChain(keyStoreInfo, certificateRequestDTO, certificateChain);
    }

    private List<Certificate> getCertificatesForDownload() throws IOException, CertificateException {
        final List<Certificate> certificates = new ArrayList<Certificate>();
        certificates.add(setUPData.createSubCACertificate("certificates/ARJ_Root-35c35df3596fc0e6-1450954693459.cer"));
        return certificates;
    }

    private KeyStoreInfo getKeyStoreInfo() {

        KeyStoreInfo keyStoreInfo = new KeyStoreInfo();
        keyStoreInfo.setAliasName(aliasName);
        keyStoreInfo.setFilePath(filePath);
        keyStoreInfo.setKeyStoreType(KeyStoreType.JKS);
        keyStoreInfo.setPassword(password);
        return keyStoreInfo;

    }

    private com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo buildKeyStoreInfoModel(final String alias, final char[] password, final byte[] keyStoreContent) {

        final com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo keyStoreInfo = new com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo();
        keyStoreInfo.setPassword(password);
        keyStoreInfo.setAlias(alias);
        keyStoreInfo.setKeyStoreFileData(keyStoreContent);

        return keyStoreInfo;
    }

    public KeyStore initializeKeyStore(final KeyStoreInfo keyStoreInfo) throws CertificateException, IOException, KeyStoreException, NoSuchAlgorithmException {

        KeyStore keyStore = null;

        if (keyStoreInfo.getKeyStoreType().equals(KeyStoreType.PKCS12)) {
            keyStore = KeyStore.getInstance(keyStoreInfo.getKeyStoreType().name(), new BouncyCastleProvider());

        } else {
            keyStore = KeyStore.getInstance(keyStoreInfo.getKeyStoreType().name());
        }
        keyStore.load(null, null);

        return keyStore;
    }
}
