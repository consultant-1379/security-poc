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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.persistence;

import static org.junit.Assert.*;

import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.inject.Inject;
import javax.persistence.EntityManager;
import javax.persistence.Query;

import org.bouncycastle.cert.CertException;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.internal.verification.Times;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.kaps.api.KeyAccessProviderService;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.kaps.model.KeyPairStatus;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequestStatus;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.BaseTest;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.*;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.core.common.utils.DateUtil;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.CertificateException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateGenerationException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateException;

@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("PMD.UnusedPrivateField")
public class PersistenceHelperTest extends BaseTest {

    @InjectMocks
    private CertificatePersistenceHelper persistenceHelper;

    @Mock
    private PersistenceManager persistenceManager;

    @Mock
    private DateUtil dateUtil;

    @Mock
    private KeyAccessProviderService keyAccessProviderServiceMock;

    @Mock
    EntityManager entityManager;

    @Mock
    Query query;

    private EntityInfoData entityData;
    private CertificateAuthorityData certificateAuthorityData;
    private CertificateData certificateData;
    private String cAName;
    private String entityName;
    private CertificateRequestData certificateRequestData;
    private CertificateGenerationInfo certificateGenerationInfo;
    private Set<CertificateData> certificates;
    private KeyPair keyPair;
    private X509Certificate x509Certificate;
    private KeyIdentifierData keyData;
    private CertificateGenerationInfoData certificateGenerationInfoData;
    private KeyIdentifierData keyIdentifierData;
    private static final String ENTITY_CERTIFICATES_BY_ENITYNAME_AND_STATUS = "select c from CertificateData c where c.status in(:statusList) and c.id in(select p.id from EntityInfoData ec inner join ec.certificateDatas p  WHERE ec.name = :name) ORDER BY c.id DESC";

    /**
     * Prepares initial data.
     * 
     * @throws NoSuchAlgorithmException
     * @throws IOException
     * @throws InvalidKeyException
     */
    @Before
    public void setUp() throws NoSuchAlgorithmException, InvalidKeyException, IOException {

        certificates = new HashSet<CertificateData>();
        certificateData = prepareCertificateData();
        certificates.add(certificateData);
        keyData = new KeyIdentifierData();
        certificateGenerationInfoData = new CertificateGenerationInfoData();
        keyIdentifierData = new KeyIdentifierData();

        entityData = setEntityData(certificates);
        setCertificateRequestData();

        cAName = "ENM_SubCA";
        entityName = "'ERBS";
        certificateGenerationInfo = new CertificateGenerationInfo();

        final Algorithm signatureAlgorithm = prepareSignatureAlgorithm();
        final Algorithm keyGenerationAlgorithm = prepareKeyGenerationAlgorithm();

        keyPair = generateKeyPair(keyGenerationAlgorithm.getName(), keyGenerationAlgorithm.getKeySize());

        certificateGenerationInfo.setSignatureAlgorithm(signatureAlgorithm);
        certificateGenerationInfo.setKeyGenerationAlgorithm(keyGenerationAlgorithm);

        certificateAuthorityData = setCertificateAuthorityData(certificates);
        certificateAuthorityData.setName(cAName);
        certificateGenerationInfoData.setcAEntityInfo(certificateAuthorityData);
    }

    /**
     * Method to test getting of {@link CertificateAuthorityData} from database.
     */
    @Test
    public void testGetCAData() {
        Mockito.when(persistenceManager.findEntitiesByAttributes(Mockito.any(Class.class), Mockito.anyMap())).thenReturn(Arrays.asList(certificateAuthorityData));
        final CertificateAuthorityData caData = persistenceHelper.getCA(cAName);

        assertEquals(certificateAuthorityData.getName(), caData.getName());
        assertEquals(certificateAuthorityData.getStatus(), caData.getStatus());
    }

    /**
     * Method to test occurrence of exception {@link CertificateAuthorityDoesNotExistException} when getCAData method is called.
     */
    @Test(expected = CoreEntityNotFoundException.class)
    public void testGetCAData_CertificateAuthorityDoesNotExistException() {
        final List<CertificateAuthorityData> certificateAuthorityDatas = new ArrayList<CertificateAuthorityData>();

        Mockito.when(persistenceManager.findEntitiesByAttributes(Mockito.any(Class.class), Mockito.anyMap())).thenReturn(certificateAuthorityDatas);
        persistenceHelper.getCA("CANotExist");
    }

    /**
     * Method to test updation of {@link CertificateRequestData} from database.
     */
    @Test
    public void testUpdateCSR() {
        Mockito.when(persistenceManager.updateEntity(certificateRequestData)).thenReturn(certificateRequestData);
        persistenceHelper.updateCSR(certificateRequestData);

        Mockito.verify(persistenceManager).updateEntity(certificateRequestData);
    }

    /**
     * Method to test storing of {@link EntityInfoData} in the database.
     */
    @Test
    public void testStoreAndReturnEntityData() {

        Mockito.doNothing().when(persistenceManager).createEntity(entityData);

        final EntityInfoData entityDataActual = persistenceHelper.storeAndReturnEntityData(entityData);

        assertNotNull(entityDataActual);
        assertEquals(entityData.getName(), entityDataActual.getName());

    }

    /**
     * Method to test occurrence of {@link CertificateGenerationException} when StoreAndReturnEntityData method is called.
     */
    @Test
    public void testStoreAndReturnEntityData_EntityExistsException() {
        Mockito.doThrow(new javax.persistence.EntityExistsException(ErrorMessages.ENTITY_ALREADY_EXISTS_IN_DATABASE)).when(persistenceManager).createEntity(Mockito.any());
        try {
            persistenceHelper.storeAndReturnEntityData(entityData);
            fail("Should throw CertificateGenerationException");
        } catch (CoreEntityAlreadyExistsException entityExistsException) {
            assertTrue(entityExistsException.getMessage().contains(ErrorMessages.ENTITY_ALREADY_EXISTS_IN_DATABASE));
        }
    }

    /**
     * Method to test storing of {@link Certificate} in the database.
     * 
     * @throws CertificateException
     * @throws IOException
     * @throws java.security.cert.CertificateException
     */
    @Test
    public void testStoreAndReturnCertificate() throws IOException, java.security.cert.CertificateException {

        x509Certificate = getCertificate("src/test/resources/MyRoot.crt");

        Mockito.doNothing().when(persistenceManager).createEntity(certificateData);
        Mockito.when(persistenceManager.findEntitiesByAttributes(Mockito.any(Class.class), Mockito.anyMap())).thenReturn(Arrays.asList(certificateRequestData));

        certificateData = persistenceHelper.storeAndReturnCertificate(x509Certificate, certificateGenerationInfo, certificateAuthorityData, certificateAuthorityData, keyIdentifierData);

        assertNotNull(certificateData);
        assertEquals(x509Certificate.getNotBefore(), certificateData.getNotBefore());
        assertEquals(x509Certificate.getNotAfter(), certificateData.getNotAfter());
        assertEquals(x509Certificate.getSerialNumber() + "", certificateData.getSerialNumber());

    }

    /**
     * Method to test occurrence of exception of {@link CertificateGenerationException} when StoreAndReturnCertificate method is called.
     * 
     * @throws CertificateException
     * @throws IOException
     * @throws CertificateEncodingException
     */
    @Test
    public void testStoreAndReturnCertificate_CertificateEncodingException() throws CertificateException, IOException, CertificateEncodingException {
        x509Certificate = Mockito.mock(X509Certificate.class);

        Mockito.when(x509Certificate.getSerialNumber()).thenReturn(new BigInteger("12345"));
        Mockito.doThrow(new CertificateEncodingException(ErrorMessages.CERTIFICATE_ENCODING_EXCEPTION)).when(x509Certificate).getEncoded();

        try {
            persistenceHelper.storeAndReturnCertificate(x509Certificate, certificateGenerationInfo, certificateAuthorityData, certificateAuthorityData, keyIdentifierData);
            fail("Should throw CertificateGenerationException");
        } catch (InvalidCertificateException certificateGenerationException) {
            assertTrue(certificateGenerationException.getMessage().contains(ErrorMessages.CERTIFICATE_ENCODING_EXCEPTION));
        }

    }

    /**
     * Method to test storing of {@link CertificateAuthorityData} in the database.
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testStoreAndReturnCertificateAuthority() throws IOException {

        Mockito.doNothing().when(persistenceManager).createEntity(certificateAuthorityData);

        final CertificateAuthorityData certificateAuthorityDataActual = persistenceHelper.storeAndReturnCertificateAuthority(certificateAuthorityData);

        assertNotNull(certificateAuthorityDataActual);
        assertEquals(certificateAuthorityData.getName(), certificateAuthorityDataActual.getName());
        assertEquals(certificateAuthorityData.getStatus(), certificateAuthorityDataActual.getStatus());
    }

    /**
     * Method to test occurrence of exception {@link CertificateGenerationException} when storeAndReturnCertificateAuthority called.
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test
    public void testStoreAndReturnCertificateAuthority_CAEntityExistsException() throws IOException {
        Mockito.doThrow(new javax.persistence.EntityExistsException(ErrorMessages.ENTITY_ALREADY_EXISTS_IN_DATABASE)).when(persistenceManager).createEntity(Mockito.any());
        try {
            persistenceHelper.storeAndReturnCertificateAuthority(certificateAuthorityData);
            fail("Should throw CAEntityExistsException");
        } catch (CoreEntityAlreadyExistsException cAEntityExistsException) {
            assertTrue(cAEntityExistsException.getMessage().contains(ErrorMessages.ENTITY_ALREADY_EXISTS_IN_DATABASE));
        }
    }

    /**
     * Method to test update of {@link CertificateAuthorityData} in the database.
     */
    @Test
    public void testUpdateCertificateAuthorityData() {

        Mockito.doNothing().when(persistenceManager).createEntity(certificateData);

        Mockito.when(persistenceManager.updateEntity(certificateAuthorityData)).thenReturn(certificateAuthorityData);

        persistenceHelper.updateCAWithActiveCertificate(certificateData, certificateAuthorityData, null, CAStatus.ACTIVE);

        Mockito.verify(persistenceManager, new Times(2)).updateEntity(certificateAuthorityData);

    }

    /**
     * Method to test update if {@link EntityInfoData} in the database.
     */
    @Test
    public void testUpdateEntityData() {
        Mockito.when(persistenceManager.updateEntity(entityData)).thenReturn(entityData);
        Mockito.doNothing().when(persistenceManager).refresh(entityData);
        Mockito.when(persistenceManager.updateEntity(entityData)).thenReturn(entityData);
        final List<CertificateData> certificateDataList = new ArrayList<CertificateData>();
        certificateDataList.add(certificateData);
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(ENTITY_CERTIFICATES_BY_ENITYNAME_AND_STATUS)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(certificateDataList);

        persistenceHelper.updateEntityData(certificateData, entityData, certificateAuthorityData, EntityStatus.ACTIVE);

        Mockito.verify(persistenceManager, new Times(1)).updateEntity(entityData);
    }

    /**
     * Method to test getting of private key from the database.
     * 
     * @throws IOException
     *             {@link IOException}
     */
    @Test(expected = CoreEntityNotFoundException.class)
    public void testGetIssuerPrivateKey_WithIssuerNull() throws IOException {
        final List<CertificateAuthorityData> certificateAuthorityDatas = new ArrayList<CertificateAuthorityData>();

        Mockito.when(persistenceManager.findEntitiesByAttributes(Mockito.any(Class.class), Mockito.anyMap())).thenReturn(certificateAuthorityDatas);

        persistenceHelper.getCA(cAName);
        persistenceHelper.getKeyIdentifier(cAName);

    }

    /**
     * Method to test getting of key generation {@link AlgorithmData} from database.
     */
    @Test
    public void testAlgorithmData_KeyGeneration() {
        final AlgorithmData algorithmData = setKeyGenerationAlgorithmData();

        Mockito.when(persistenceManager.findEntitiesByAttributes(Mockito.any(Class.class), Mockito.anyMap())).thenReturn(Arrays.asList(algorithmData));
        final AlgorithmData algorithmDataHelper = persistenceHelper.getAlgorithmData(certificateGenerationInfo.getKeyGenerationAlgorithm());

        assertNotNull(algorithmDataHelper);
        assertEquals(algorithmData.getId(), algorithmDataHelper.getId());
        assertEquals(algorithmData.getName(), algorithmDataHelper.getName());
        assertEquals(algorithmData.getType(), algorithmDataHelper.getType());
        assertEquals(algorithmData.getKeySize(), algorithmDataHelper.getKeySize());
    }

    /**
     * Method to test getting of key generation {@link AlgorithmData} from database.
     */
    @Test
    public void testAlgorithmData_Signature() {
        final AlgorithmData algorithmData = setSignatureAlgorithmData();

        Mockito.when(persistenceManager.findEntitiesByAttributes(Mockito.any(Class.class), Mockito.anyMap())).thenReturn(Arrays.asList(algorithmData));
        final AlgorithmData algorithmDataHelper = persistenceHelper.getAlgorithmData(certificateGenerationInfo.getSignatureAlgorithm());

        assertNotNull(algorithmDataHelper);
        assertEquals(algorithmData.getId(), algorithmDataHelper.getId());
        assertEquals(algorithmData.getName(), algorithmDataHelper.getName());
        assertEquals(algorithmData.getType(), algorithmDataHelper.getType());
        assertEquals(algorithmData.getKeySize(), algorithmDataHelper.getKeySize());
    }

    /**
     * Method to test getting of key generation {@link AlgorithmData} from database.
     */
    @Test
    public void testAlgorithmData_nullObject() {
        setSignatureAlgorithmData();

        final List<AlgorithmData> algorithmDatas = new ArrayList<AlgorithmData>();

        Mockito.when(persistenceManager.findEntitiesByAttributes(Mockito.any(Class.class), Mockito.anyMap())).thenReturn(algorithmDatas);
        final AlgorithmData algorithmDataHelper = persistenceHelper.getAlgorithmData(certificateGenerationInfo.getSignatureAlgorithm());
        assertNull(algorithmDataHelper);
    }

    /**
     * Method to test updation of {@link CertificateGenerationInfo} with certificate.
     */
    @Test
    public void testUpdateCertificateGenerationInfo() {

        Mockito.when(persistenceManager.updateEntity(certificateGenerationInfoData)).thenReturn(certificateGenerationInfoData);
        persistenceHelper.updateCertificateGenerationInfo(certificateGenerationInfoData, certificateData);

        Mockito.verify(persistenceManager).updateEntity(certificateGenerationInfoData);
    }

    /**
     * Method to test creation of {@link keyData} in the database.
     */
    @Test
    public void testStoreAndReturnKeyData() {

        Mockito.doNothing().when(persistenceManager).createEntity(keyData);
        persistenceHelper.storeAndReturnKeyData(keyData);

        Mockito.verify(persistenceManager).createEntity(keyData);
    }

    /**
     * Method to test occurrence of {@link CertificateGenerationException} when StoreAndReturnEntityData method is called.
     */
    @Test
    public void testStoreAndReturnKeyData_EntityExistsException() {
        Mockito.doThrow(new javax.persistence.EntityExistsException(ErrorMessages.ENTITY_ALREADY_EXISTS_IN_DATABASE)).when(persistenceManager).createEntity(Mockito.any());
        try {
            persistenceHelper.storeAndReturnKeyData(keyData);
            fail("Should throw CertificateGenerationException");
        } catch (CoreEntityAlreadyExistsException entityExistsException) {
            assertTrue(entityExistsException.getMessage().contains(ErrorMessages.ENTITY_ALREADY_EXISTS_IN_DATABASE));
        }
    }

    /**
     * Method to test get {@link EntityInfoData} from the database.
     */
    @Test
    public void testGetEntityData() {

        Mockito.when(persistenceManager.findEntitiesByAttributes(Mockito.any(Class.class), Mockito.anyMap())).thenReturn(Arrays.asList(entityData));
        final EntityInfoData entityInfoData = persistenceHelper.getEntityData(entityName);

        assertEquals(entityData.getName(), entityInfoData.getName());
        assertEquals(entityData.getStatus(), entityInfoData.getStatus());
    }

    /**
     * Method to test occurrence of exception {@link CertificateAuthorityDoesNotExistException} when getCAData method is called.
     */
    @Test
    public void testGetEntityData_WithNull() {
        final List<EntityInfoData> entityInfoDatas = new ArrayList<EntityInfoData>();

        Mockito.when(persistenceManager.findEntitiesByAttributes(Mockito.any(Class.class), Mockito.anyMap())).thenReturn(entityInfoDatas);
        persistenceHelper.getEntityData("InvalidEntity");
    }

    /**
     * Test method to check update of CA with ACTIVE keys.
     */
    @Test
    public void testUpdateCAWithActiveKeys() {

        final KeyIdentifierData keyIdentifierData = getKeyIdentifierData();
        Mockito.when(persistenceManager.updateEntity(certificateAuthorityData)).thenReturn(certificateAuthorityData);
        persistenceHelper.updateCAWithActiveKeys(certificateAuthorityData, keyIdentifierData);
    }

    @Test
    public void testGetKeyIdentifier() {

        Mockito.when(persistenceManager.findEntitiesByAttributes(Mockito.any(Class.class), Mockito.anyMap())).thenReturn(Arrays.asList(certificateAuthorityData));
        final KeyIdentifierData keyIdentifierData = getKeyIdentifierData();
        final Set<KeyIdentifierData> cAKeys = new HashSet<KeyIdentifierData>();
        cAKeys.add(keyIdentifierData);
        certificateAuthorityData.setcAKeys(cAKeys);
        final KeyIdentifier keyIdentifier = persistenceHelper.getKeyIdentifier("ENM_SubCA");

        assertNotNull(keyIdentifier);
        assertEquals(keyIdentifierData.getKeyIdentifier(), keyIdentifier.getId());
    }

    @Test
    public void testUpdateCAKeysToInactive() {

        Mockito.when(persistenceManager.findEntitiesByAttributes(Mockito.any(Class.class), Mockito.anyMap())).thenReturn(Arrays.asList(certificateAuthorityData));
        final KeyIdentifierData keyIdentifierData = getKeyIdentifierData();
        final Set<KeyIdentifierData> cAKeys = new HashSet<KeyIdentifierData>();
        cAKeys.add(keyIdentifierData);
        certificateAuthorityData.setcAKeys(cAKeys);
        persistenceHelper.updateKeyIdentifierStatus(keyIdentifierData, KeyPairStatus.INACTIVE);

        Mockito.when(persistenceManager.updateEntity(keyIdentifierData)).thenReturn(keyIdentifierData);
        Mockito.verify(persistenceManager).updateEntity(keyIdentifierData);

    }

    @Test
    public void testActiveKeyIdentifier() {

        Mockito.when(persistenceManager.findEntitiesByAttributes(Mockito.any(Class.class), Mockito.anyMap())).thenReturn(Arrays.asList(certificateAuthorityData));
        final KeyIdentifierData keyIdentifierData = getKeyIdentifierData();
        final Set<KeyIdentifierData> cAKeys = new HashSet<KeyIdentifierData>();
        cAKeys.add(keyIdentifierData);
        certificateAuthorityData.setcAKeys(cAKeys);
        final KeyIdentifierData keyIdentifierDataExpected = persistenceHelper.getActiveKeyIdentifier(cAName);

        assertNotNull(keyIdentifierDataExpected);
        assertEquals(keyIdentifierData.getKeyIdentifier(), keyIdentifierDataExpected.getKeyIdentifier());
        assertEquals(keyIdentifierDataExpected.getStatus(), keyIdentifierData.getStatus());

    }

    @Test
    public void testGetCertificateData() throws CertException {

        Mockito.when(persistenceManager.findEntity(Mockito.any(Class.class), Mockito.anyLong())).thenReturn(certificateData);
        final com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate certificate = new com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate();

        final CertificateData certificateData = persistenceHelper.getCertificateData(certificate);
        assertNotNull(certificateData);
    }

    private CertificateAuthorityData setCertificateAuthorityData(final Set<CertificateData> certificates) {
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setCertificateDatas(certificates);
        certificateAuthorityData.setName(cAName);
        certificateAuthorityData.setRootCA(false);
        certificateAuthorityData.setStatus(CAStatus.ACTIVE);
        certificateAuthorityData.setIssuerCA(null);
        return certificateAuthorityData;
    }

    private EntityInfoData setEntityData(final Set<CertificateData> certificates) {
        final EntityInfoData entityData = new EntityInfoData();
        entityData.setCertificateDatas(certificates);
        entityData.setName("entity");
        entityData.setId(1);
        return entityData;
    }

    private AlgorithmData setKeyGenerationAlgorithmData() {
        final AlgorithmData algorithmData = new AlgorithmData();
        algorithmData.setKeySize(1024);
        algorithmData.setName("RSA");
        algorithmData.setType(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
        return algorithmData;
    }

    private AlgorithmData setSignatureAlgorithmData() {
        final AlgorithmData algorithmData = new AlgorithmData();
        algorithmData.setName("SHA1WITHRSA");
        algorithmData.setType(AlgorithmType.SIGNATURE_ALGORITHM);
        return algorithmData;
    }

    private CertificateRequestData setCertificateRequestData() {
        certificateRequestData = new CertificateRequestData();
        certificateRequestData.setId(1);
        certificateRequestData.setStatus(CertificateRequestStatus.ISSUED.getId());
        return certificateRequestData;
    }

    private KeyIdentifierData getKeyIdentifierData() {

        final KeyIdentifierData keyIdentifierData = new KeyIdentifierData();
        keyIdentifierData.setId(1L);
        keyIdentifierData.setKeyIdentifier("K000001");
        keyIdentifierData.setStatus(KeyPairStatus.ACTIVE);

        return keyIdentifierData;
    }
}
