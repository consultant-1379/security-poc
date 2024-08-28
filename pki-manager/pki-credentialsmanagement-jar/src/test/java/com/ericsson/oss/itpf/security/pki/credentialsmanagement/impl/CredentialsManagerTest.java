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
package com.ericsson.oss.itpf.security.pki.credentialsmanagement.impl;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.*;
import java.security.cert.*;
import java.util.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.resources.Resource;
import com.ericsson.oss.itpf.security.pki.common.keystore.*;
import com.ericsson.oss.itpf.security.pki.common.keystore.exception.AliasNotFoundException;
import com.ericsson.oss.itpf.security.pki.common.keystore.exception.KeyStoreTypeNotSupportedException;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.exception.CredentialsManagementServiceException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.helper.CredentialsHelper;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.xml.model.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreInfo;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.model.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.impl.EntityCertificateManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;

@RunWith(MockitoJUnitRunner.class)
public class CredentialsManagerTest {

    @InjectMocks
    CredentialsManager credentialsManager;

    @Mock
    private EntityCertificateManager entityCertificateManager;

    @Mock
    private PkiManagerCredentialsCertRequestXmlReader pkiCredentialCertRequestXmlReader;

    @Mock
    private CredentialsHelper credentialsHelper;

    @Mock
    private KeyStoreFileReader keyStorefileReader;

    @Mock
    private KeyStoreFileWriterFactory keyStoreFileWriterFactory;

    @Mock
    private Logger logger;

    @Mock
    private CertificateType certificateType;

    @Mock
    SubjectType subjectType;

    @Mock
    KeyStoreInfo keyStoreInfo;
    @Mock
    Certificate certificate;

    @Mock
    KeyStoreFileWriter keyStoreFileWriter;
    @Mock
    Resource resource;

    @Mock
    KeyPairType keyPairType;

    @Mock
    StoreType store;

    @Mock
    private CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    private SystemRecorder systemRecorder;

    @Mock
    private com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo keyStoreInfoObj;

    private String keyPairAlgorithm;

    private List<Certificate> trustCertificateList = new ArrayList<Certificate>();

    private String entityName = "ENM_Entity";

    private String entityProfileName;

    private Integer keyPairSize;

    private Set<X509Certificate> trustCertificateSet = new HashSet<X509Certificate>();

    private PrivateKey signerPrivateKey;

    private X509Certificate signerCertificate;

    @Test
    public void testSetupPkiCredentials() throws KeyStoreTypeNotSupportedException, CertificateException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, IOException {

        trustCertificateList.add(certificate);
        Mockito.when(pkiCredentialCertRequestXmlReader.getSubjectType()).thenReturn(subjectType);

        Mockito.when(pkiCredentialCertRequestXmlReader.getSubjectType().getEntityName()).thenReturn(entityName);
        Mockito.when(credentialsHelper.resolveHostName(entityName)).thenReturn(entityName);

        Mockito.when(pkiCredentialCertRequestXmlReader.getSubjectType().getDistinguishName()).thenReturn(entityName);

        Mockito.when(pkiCredentialCertRequestXmlReader.getEndEntityProfileName()).thenReturn(entityProfileName);

        Mockito.when(pkiCredentialCertRequestXmlReader.getStore(KeyStoreType.PKCS12)).thenReturn(store);

        Mockito.when(pkiCredentialCertRequestXmlReader.getKeyPairType()).thenReturn(keyPairType);
        Mockito.when(pkiCredentialCertRequestXmlReader.getKeyPairType().getKeyPairSize()).thenReturn(keyPairSize);
        Mockito.when(pkiCredentialCertRequestXmlReader.getKeyPairType().getKeyPairAlgorithm()).thenReturn(keyPairAlgorithm);

        Mockito.when(pkiCredentialCertRequestXmlReader.getStore(KeyStoreType.JKS)).thenReturn(store);
        Mockito.when(store.getStorePassword()).thenReturn("keyStorePassword");

        Mockito.when(entityCertificateManager.generateKeyStore(entityName, "keyStorePassword".toCharArray(), KeyStoreType.PKCS12, RequestType.NEW)).thenReturn(keyStoreInfo);

        Mockito.when(entityCertificateManager.getTrustCertificates(entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(trustCertificateList);

        Mockito.when(keyStoreFileWriterFactory.getKeystoreFileWriterInstance((com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo) Mockito.anyObject())).thenReturn(keyStoreFileWriter);

        Mockito.when(
                keyStoreFileWriterFactory.getKeystoreFileWriterInstance((com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo) Mockito.anyObject()).createCertificateKeyStore(
                        (List<Certificate>) Mockito.anyList(), (com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo) Mockito.anyObject())).thenReturn(resource);

        credentialsManager.generatePkiCredentials();
        Mockito.verify(entityCertificateManager).getTrustCertificates(entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);
    }

    /**
     * Method to test setupPkiCredentials for failure scenario, while generating key store.
     */
    @Test(expected = CredentialsManagementServiceException.class)
    public void testSetupPkiCredentials_failure_generating_key_store() throws KeyStoreTypeNotSupportedException, CertificateException, KeyStoreException, NoSuchAlgorithmException,
            NoSuchProviderException, IOException {

        trustCertificateList.add(certificate);
        Mockito.when(pkiCredentialCertRequestXmlReader.getSubjectType()).thenReturn(subjectType);

        Mockito.when(pkiCredentialCertRequestXmlReader.getSubjectType().getEntityName()).thenReturn(entityName);
        Mockito.when(credentialsHelper.resolveHostName(entityName)).thenReturn(entityName);

        Mockito.when(pkiCredentialCertRequestXmlReader.getSubjectType().getDistinguishName()).thenReturn(entityName);

        Mockito.when(pkiCredentialCertRequestXmlReader.getEndEntityProfileName()).thenReturn(entityProfileName);

        Mockito.when(pkiCredentialCertRequestXmlReader.getStore(KeyStoreType.PKCS12)).thenReturn(store);

        Mockito.when(pkiCredentialCertRequestXmlReader.getKeyPairType()).thenReturn(keyPairType);
        Mockito.when(pkiCredentialCertRequestXmlReader.getKeyPairType().getKeyPairSize()).thenReturn(keyPairSize);
        Mockito.when(pkiCredentialCertRequestXmlReader.getKeyPairType().getKeyPairAlgorithm()).thenReturn(keyPairAlgorithm);

        Mockito.when(pkiCredentialCertRequestXmlReader.getStore(KeyStoreType.JKS)).thenReturn(store);
        Mockito.when(store.getStorePassword()).thenReturn("keyStorePassword");

        Mockito.when(entityCertificateManager.generateKeyStore(entityName, "keyStorePassword".toCharArray(), KeyStoreType.PKCS12, RequestType.NEW)).thenThrow(
                new AlgorithmNotFoundException("Error while generating key store file for pki-manager credentials"));

        credentialsManager.generatePkiCredentials();
    }

    /**
     * Method to test setupPkiCredentials for failure scenario, while generating trust store.
     */
    @Test(expected = CredentialsManagementServiceException.class)
    public void testSetupPkiCredentials_failure_generating_trust_store() throws KeyStoreTypeNotSupportedException, CertificateException, KeyStoreException, NoSuchAlgorithmException,
            NoSuchProviderException, IOException {

        trustCertificateList.add(certificate);

        Mockito.when(pkiCredentialCertRequestXmlReader.getSubjectType()).thenReturn(subjectType);

        Mockito.when(pkiCredentialCertRequestXmlReader.getSubjectType().getEntityName()).thenReturn(entityName);
        Mockito.when(credentialsHelper.resolveHostName(entityName)).thenReturn(entityName);

        Mockito.when(pkiCredentialCertRequestXmlReader.getSubjectType().getDistinguishName()).thenReturn(entityName);

        Mockito.when(pkiCredentialCertRequestXmlReader.getEndEntityProfileName()).thenReturn(entityProfileName);

        Mockito.when(pkiCredentialCertRequestXmlReader.getStore(KeyStoreType.PKCS12)).thenReturn(store);

        Mockito.when(pkiCredentialCertRequestXmlReader.getKeyPairType()).thenReturn(keyPairType);
        Mockito.when(pkiCredentialCertRequestXmlReader.getKeyPairType().getKeyPairSize()).thenReturn(keyPairSize);
        Mockito.when(pkiCredentialCertRequestXmlReader.getKeyPairType().getKeyPairAlgorithm()).thenReturn(keyPairAlgorithm);

        Mockito.when(pkiCredentialCertRequestXmlReader.getStore(KeyStoreType.JKS)).thenReturn(store);
        Mockito.when(store.getStorePassword()).thenReturn("keyStorePassword");

        Mockito.when(entityCertificateManager.generateKeyStore(entityName, "keyStorePassword".toCharArray(), KeyStoreType.PKCS12, RequestType.NEW)).thenReturn(keyStoreInfo);

        Mockito.when(entityCertificateManager.getTrustCertificates(entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenThrow(
                new EntityNotFoundException("Error while generating trust store file for pki-manager credentials"));
        Mockito.when(keyStoreFileWriterFactory.getKeystoreFileWriterInstance((com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo) Mockito.anyObject())).thenReturn(keyStoreFileWriter);

        Mockito.when(
                keyStoreFileWriterFactory.getKeystoreFileWriterInstance((com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo) Mockito.anyObject()).createCertificateKeyStore(
                        (List<Certificate>) Mockito.anyList(), (com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo) Mockito.anyObject())).thenReturn(resource);

        credentialsManager.generatePkiCredentials();
    }

    /**
     * Method to test getTrustCertificateSet.
     */
    @Test
    public void testGetTrustCertificateSet() throws KeyStoreException {

        Mockito.when(keyStorefileReader.readCertificates(keyStoreInfoObj)).thenReturn(trustCertificateSet);
        credentialsManager.getTrustCertificateSet();
        Mockito.verify(keyStorefileReader).readCertificates((com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo) Mockito.anyObject());
    }

    @Test(expected = CredentialsManagementServiceException.class)
    public void testGetTrustCertificateSetKeyStoreException() throws KeyStoreException {
        Mockito.when(keyStorefileReader.readCertificates((com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo) Mockito.anyObject())).thenThrow(new KeyStoreException());
        credentialsManager.getTrustCertificateSet();
    }

    /**
     * Method to test getSignerPrivateKey.
     */
    @Test
    public void testGetSignerPrivateKey() {

        Mockito.when(keyStorefileReader.readPrivateKey(keyStoreInfoObj)).thenReturn(signerPrivateKey);
        credentialsManager.getSignerPrivateKey();
        Mockito.verify(keyStorefileReader).readPrivateKey((com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo) Mockito.anyObject());
    }

    @Test(expected = CredentialsManagementServiceException.class)
    public void testGetSignerPrivateKeyException() {

        Mockito.when(keyStorefileReader.readPrivateKey((com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo) Mockito.anyObject())).thenThrow(
                new AliasNotFoundException(Mockito.anyString()));
        credentialsManager.getSignerPrivateKey();
    }

    /**
     * Method to test getSignerCertificate.
     */
    @Test
    public void testGetSignerCertificate() {

        Mockito.when((X509Certificate) keyStorefileReader.readCertificate(keyStoreInfoObj)).thenReturn(signerCertificate);
        credentialsManager.getSignerCertificate();
        Mockito.verify(keyStorefileReader).readCertificate((com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo) Mockito.anyObject());
    }

    @Test(expected = CredentialsManagementServiceException.class)
    public void testGetSignerCertificateException() {

        Mockito.when((X509Certificate) keyStorefileReader.readCertificate((com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo) Mockito.anyObject())).thenThrow(
                new AliasNotFoundException(Mockito.anyString()));
        credentialsManager.getSignerCertificate();
    }

    @Test
    public void testGeneratePkiCredentials() throws KeyStoreTypeNotSupportedException, CertificateException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, IOException {

        trustCertificateList.add(certificate);
        Mockito.when(pkiCredentialCertRequestXmlReader.getSubjectType()).thenReturn(subjectType);

        Mockito.when(pkiCredentialCertRequestXmlReader.getSubjectType().getEntityName()).thenReturn(entityName);
        Mockito.when(credentialsHelper.resolveHostName(entityName)).thenReturn(entityName);

        Mockito.when(pkiCredentialCertRequestXmlReader.getSubjectType().getDistinguishName()).thenReturn(entityName);

        Mockito.when(pkiCredentialCertRequestXmlReader.getEndEntityProfileName()).thenReturn(entityProfileName);

        Mockito.when(pkiCredentialCertRequestXmlReader.getStore(KeyStoreType.PKCS12)).thenReturn(store);

        Mockito.when(pkiCredentialCertRequestXmlReader.getKeyPairType()).thenReturn(keyPairType);
        Mockito.when(pkiCredentialCertRequestXmlReader.getKeyPairType().getKeyPairSize()).thenReturn(keyPairSize);
        Mockito.when(pkiCredentialCertRequestXmlReader.getKeyPairType().getKeyPairAlgorithm()).thenReturn(keyPairAlgorithm);

        Mockito.when(pkiCredentialCertRequestXmlReader.getStore(KeyStoreType.JKS)).thenReturn(store);
        Mockito.when(store.getStorePassword()).thenReturn("keyStorePassword");

        Mockito.when(entityCertificateManager.generateKeyStore(entityName, "keyStorePassword".toCharArray(), KeyStoreType.PKCS12, RequestType.NEW)).thenReturn(keyStoreInfo);

        Mockito.when(entityCertificateManager.getTrustCertificates(entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(trustCertificateList);

        Mockito.when(keyStoreFileWriterFactory.getKeystoreFileWriterInstance((com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo) Mockito.anyObject())).thenReturn(keyStoreFileWriter);

        Mockito.when(
                keyStoreFileWriterFactory.getKeystoreFileWriterInstance((com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo) Mockito.anyObject()).createCertificateKeyStore(
                        (List<Certificate>) Mockito.anyList(), (com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo) Mockito.anyObject())).thenReturn(resource);
        Mockito.when(credentialsHelper.checkForFileExist(Mockito.anyString())).thenReturn(true);
        signerCertificate = getX509Certificate("ENMRootCA.crt");
        Mockito.when((X509Certificate) keyStorefileReader.readCertificate(keyStoreInfoObj)).thenReturn(signerCertificate);

        Mockito.when(pkiCredentialCertRequestXmlReader.getOverlapPeriod()).thenReturn("P2Y4M30DT17H5M57.123S");
        Mockito.when(keyStorefileReader.readCertificate(Mockito.<com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo> anyObject())).thenReturn(signerCertificate);

        credentialsManager.generatePkiCredentials();
        Mockito.verify(entityCertificateManager).getTrustCertificates(entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);
    }

    @Test
    public void testGeneratePkiCredentialsException() throws KeyStoreTypeNotSupportedException, CertificateException, KeyStoreException, NoSuchAlgorithmException, NoSuchProviderException, IOException {

        trustCertificateList.add(certificate);
        Mockito.when(pkiCredentialCertRequestXmlReader.getSubjectType()).thenReturn(subjectType);

        Mockito.when(pkiCredentialCertRequestXmlReader.getSubjectType().getEntityName()).thenReturn(entityName);
        Mockito.when(credentialsHelper.resolveHostName(entityName)).thenReturn(entityName);

        Mockito.when(pkiCredentialCertRequestXmlReader.getSubjectType().getDistinguishName()).thenReturn(entityName);

        Mockito.when(pkiCredentialCertRequestXmlReader.getEndEntityProfileName()).thenReturn(entityProfileName);

        Mockito.when(pkiCredentialCertRequestXmlReader.getStore(KeyStoreType.PKCS12)).thenReturn(store);

        Mockito.when(pkiCredentialCertRequestXmlReader.getKeyPairType()).thenReturn(keyPairType);
        Mockito.when(pkiCredentialCertRequestXmlReader.getKeyPairType().getKeyPairSize()).thenReturn(keyPairSize);
        Mockito.when(pkiCredentialCertRequestXmlReader.getKeyPairType().getKeyPairAlgorithm()).thenReturn(keyPairAlgorithm);

        Mockito.when(pkiCredentialCertRequestXmlReader.getStore(KeyStoreType.JKS)).thenReturn(store);
        Mockito.when(store.getStorePassword()).thenReturn("keyStorePassword");

        Mockito.when(entityCertificateManager.generateKeyStore(entityName, "keyStorePassword".toCharArray(), KeyStoreType.PKCS12, RequestType.NEW)).thenReturn(keyStoreInfo);

        Mockito.when(entityCertificateManager.getTrustCertificates(entityName, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(trustCertificateList);

        Mockito.when(keyStoreFileWriterFactory.getKeystoreFileWriterInstance((com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo) Mockito.anyObject())).thenReturn(keyStoreFileWriter);

        Mockito.when(
                keyStoreFileWriterFactory.getKeystoreFileWriterInstance((com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo) Mockito.anyObject()).createCertificateKeyStore(
                        (List<Certificate>) Mockito.anyList(), (com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo) Mockito.anyObject())).thenReturn(resource);
        Mockito.when(credentialsHelper.checkForFileExist(Mockito.anyString())).thenReturn(true);
        signerCertificate = getX509Certificate("ENMRootCA.crt");
        Mockito.when((X509Certificate) keyStorefileReader.readCertificate(keyStoreInfoObj)).thenReturn(signerCertificate);
        Mockito.when(pkiCredentialCertRequestXmlReader.getOverlapPeriod()).thenReturn("2012-06-30T23:59:60.123456789Z");
        Mockito.when(keyStorefileReader.readCertificate(Mockito.<com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreInfo> anyObject())).thenReturn(signerCertificate);

        credentialsManager.generatePkiCredentials();

    }

    private X509Certificate getX509Certificate(final String filename) throws IOException, CertificateException {

        CertificateFactory certificateFactory;
        X509Certificate vendorCert;
        FileInputStream fileInputStream;
        String vendorCertPath = null;
        vendorCertPath = CredentialsManagerTest.class.getResource("/certificates/" + filename).getPath();
        certificateFactory = CertificateFactory.getInstance("X.509");
        fileInputStream = new FileInputStream(vendorCertPath);
        vendorCert = (X509Certificate) certificateFactory.generateCertificate(fileInputStream);
        return vendorCert;
    }
}
