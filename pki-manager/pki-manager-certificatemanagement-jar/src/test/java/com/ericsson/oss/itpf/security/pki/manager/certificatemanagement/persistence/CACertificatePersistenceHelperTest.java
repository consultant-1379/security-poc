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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.persistence;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNotNull;

import java.io.IOException;
import java.security.Security;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.util.*;

import javax.inject.Inject;
import javax.persistence.*;
import javax.xml.datatype.DatatypeFactory;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.CertificateManagementBaseTest;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.*;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.helpers.DefaultCertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.CertificateExpiryNotificationDetailsMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.extcertificate.ExtCertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.externalCA.ExternalCRLMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.certificate.CertificateModelMapperV1;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.ExtCACertificatePersistanceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidOperationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCRLException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCAAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLEncodedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.NotificationSeverity;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

/**
 * @author tcsjagc
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class CACertificatePersistenceHelperTest extends CertificateManagementBaseTest {

    @InjectMocks
    CACertificatePersistenceHelper caPersistenceHelper;

    @Mock
    static CertificateModelMapper certificateModelMapper;

    @Mock
    CertificateGenerationInfo certificateGenerationInfo;

    @Mock
    CertificateGenerationInfoData certificateGenerationInfoData;

    @Mock
    Logger logger;

    @Mock
    static PersistenceManager persistenceManager;

    @Mock
    ExternalCRLMapper crlMapper;

    @Mock
    EntityManager entityManager;

    @Mock
    Query query;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    ExtCertificateModelMapper extCertificateModelMapper;

    @Mock
    ExtCACertificatePersistanceHandler extCACertificatePersistanceHandler;

    @Mock
    CAEntityData caEntityData;

    @Mock
    DefaultCertificateExpiryNotificationDetails defaultCertExpiryNotificationDetails;

    @Mock
    CertificateExpiryNotificationDetailsMapper certExpiryNotificationDetailsMapper;

    @Mock
    CertificateModelMapperV1 certificateModelMapper_v1;

    private static SetUPData setUPData;
    private static List<TrustProfileData> trustProfileDatas = new ArrayList<TrustProfileData>();
    private static SubjectSetUPData subjectData;
    private static CertificateGenerationInfoSetUPData certificateGenerationInfoSetUPData;
    private static String caEntityName = "CAEntity1";
    private final static String CERTIFICATE_ID = "12345";
    private final static String FILE_PATH = "certificates/ENMRootCA.crt";
    private static List<Object[]> ObjectsList = new ArrayList<Object[]>();
    private static List<Certificate> certificateList = new ArrayList<Certificate>();
    private static List<CertificateData> CertificateDataList = new ArrayList<CertificateData>();
    private static List<CAEntityData> CAEntityDataList = new ArrayList<CAEntityData>();
    private static final String cANamePath = "certificateAuthorityData.name";
    private static CertificateExpiryNotificationDetails certificateExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
    private static Set<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();
    private static CertificateExpiryNotificationDetailsData certificateExpiryNotificationDetailsData = new CertificateExpiryNotificationDetailsData();
    private static Set<CertificateExpiryNotificationDetailsData> certificateExpiryNotificationDetailsDataSet = new HashSet<CertificateExpiryNotificationDetailsData>();
    private static final List<CertificateGenerationInfoData> certificateGenerationInfoDataList = new ArrayList<CertificateGenerationInfoData>();

    private String CERTIFICATE_GENERATION_INFO_QUERY = "select cgf from CertificateGenerationInfoData cgf where cgf.forExternalCA = true and cgf.cAEntityInfo in ( select ec.id from CAEntityData ec where ec.certificateAuthorityData.name = :name) ORDER BY cgf.id DESC";

    static {
        Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
    }

    /**
     * Prepares initial set up required to run the test cases.
     * 
     * @throws Exception
     */
    @BeforeClass
    public static void setUp() throws Exception {
        setUPData = new SetUPData();
        certificateList.add(getCertificate());
        final Object[] SampleQuery = new Object[] { "SerialNumber", "1", 2345 };
        subjectData = new SubjectSetUPData();
        certificateGenerationInfoSetUPData = new CertificateGenerationInfoSetUPData();
        ObjectsList.add(SampleQuery);
        CertificateDataList.add(getCertificateData());
        final TrustProfileData trustProfileData = new TrustProfileData();
        trustProfileData.setActive(true);
        trustProfileData.setName("ProfileName");
        trustProfileDatas.add(trustProfileData);
        CAEntityDataList.add(createCAEntityData(caEntityName, true));
        certificateExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.CRITICAL);
        certificateExpiryNotificationDetails.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration(Constants.DEFAULT_PERIOD_BEFORE_EXPIRY_CRITICAL));
        certificateExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration(Constants.DEFAULT_FREQUENCY_OF_NOTIFICATION_CRITICAL));
        certificateExpiryNotificationDetailsSet.add(certificateExpiryNotificationDetails);
        certificateExpiryNotificationDetailsData.setNotificationSeverity((NotificationSeverity.CRITICAL).getId());
        certificateExpiryNotificationDetailsData.setPeriodBeforeExpiry((DatatypeFactory.newInstance().newDuration(Constants.DEFAULT_PERIOD_BEFORE_EXPIRY_CRITICAL)).getDays());
        certificateExpiryNotificationDetailsData.setFrequencyOfNotification((DatatypeFactory.newInstance().newDuration(Constants.DEFAULT_FREQUENCY_OF_NOTIFICATION_CRITICAL)).getDays());
        certificateExpiryNotificationDetailsData.setNotificationMessage(Constants.EXTERNAL_CA_CERTIFICATE_EXPIRY_NOTIFICATION_MESSAGE);
        certificateExpiryNotificationDetailsDataSet.add(certificateExpiryNotificationDetailsData);

    }

    /**
     * Method to test storeCertificate method.
     * 
     * @throws Exception
     */
    @Test
    public void testStoreCertificate() throws Exception {

        final Subject subject = subjectData.getSubject(SetUPData.SUB_CA_NAME);
        final CAEntity caEntity = setUPData.getCAEntity(SetUPData.SUB_CA_NAME, subject, true);

        final Certificate certificate = setUPData.createSubCACertificate();

        final CertificateGenerationInfo certGenInfo = certificateGenerationInfoSetUPData.getCertificateGenerationInfo_CAEntity();

        final CAEntityData caEntityData = setUPData.createCAEntityData(SetUPData.SUB_CA_NAME, true);
        Mockito.when(persistenceManager.findEntity(CAEntityData.class, caEntity.getCertificateAuthority().getId())).thenReturn(caEntityData);
        CertificateData certificateData = setUPData.createCertificateData(CERTIFICATE_ID);
        certificateData.setCertificate(setUPData.getX509Certificate(FILE_PATH).getEncoded());

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);

        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);

        Mockito.when(query.getResultList()).thenReturn(Arrays.asList(certificateData));

        final CertificateGenerationInfoData certGenInfoData = new CertificateGenerationInfoData();
        Mockito.when(persistenceManager.findEntity(CertificateGenerationInfoData.class, certGenInfo.getId())).thenReturn(certGenInfoData);

        certificateData = mockCertificateData(certificate);

        Mockito.doNothing().when(persistenceManager).createEntity(certificateData);
        Mockito.when(persistenceManager.updateEntity(caEntityData)).thenReturn(caEntityData);

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, caEntity.getCertificateAuthority().getName(), cANamePath)).thenReturn(caEntityData);

        caPersistenceHelper.storeCertificate(caEntity.getCertificateAuthority().getName(), certGenInfo, certificate);

        Mockito.verify(persistenceManager).findEntity(CertificateGenerationInfoData.class, certGenInfo.getId());

    }

    /**
     * Method to test storeCertificate method when DataException occurred.
     * 
     * @throws Exception
     */
    @Test(expected = PersistenceException.class)
    public void testStoreCertificate_DataExeption() throws Exception {

        final Subject subject = subjectData.getSubject("RootCA");
        final CAEntity caEntity = setUPData.getCAEntity(SetUPData.ROOT_CA_NAME, subject, true);

        final Certificate certificate = setUPData.getCertificate("certificates/ENMRootCA.crt");

        final CertificateGenerationInfo certGenInfo = certificateGenerationInfoSetUPData.getCertificateGenerationInfo_CAEntity();

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, caEntity.getCertificateAuthority().getName(), cANamePath)).thenThrow(
                new PersistenceException("Exception while retrieving the entity from database"));

        caPersistenceHelper.storeCertificate(caEntity.getCertificateAuthority().getName(), certGenInfo, certificate);

    }

    /**
     * Method to test getCertificates method.
     *
     * @throws Exception
     */
    @Test
    public void testGetCertificates() throws Exception {

        final CertificateData certificateData = setUPData.createCertificateData("12345");
        certificateData.setCertificate(setUPData.getX509Certificate("certificates/ENMRootCA.crt").getEncoded());
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);

        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);

        Mockito.when(query.getResultList()).thenReturn(Arrays.asList(certificateData));
        final CAEntityData caEntityData = createCAEntityData(caEntityName, true);
        caEntityName = "ENMRootCA";
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, caEntityName, Constants.CA_NAME_PATH)).thenReturn(caEntityData);
        final Certificate certificate = setUPData.toCertificate(certificateData);
        Mockito.when(certificateModelMapper.toObjectModel(Arrays.asList(certificateData))).thenReturn(Arrays.asList(certificate));
        final List<CertificateData> certificateDatas = Arrays.asList(certificateData);
        List<Certificate> certificatesList = new ArrayList<Certificate>();
        certificatesList.add(certificate);
        Mockito.when(certificateModelMapper_v1.toApi(certificateDatas, MappingDepth.LEVEL_0)).thenReturn(certificatesList);
        assertCertificate(certificateData, certificatesList.get(0));

    }

    /**
     * Method to test getCertificates method when DataException occurred.
     *
     * @throws Exception
     */
    @Test(expected = PersistenceException.class)
    public void testGetCertificates_DataExeption() throws Exception {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);

        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);

        Mockito.when(query.getResultList()).thenThrow(new PersistenceException("Exception while retrieving the certificates from database"));

        caPersistenceHelper.getCertificates(SetUPData.ROOT_CA_NAME, MappingDepth.LEVEL_0, CertificateStatus.ACTIVE);

    }

    /**
     * Test Case for retrieving CAEntityData for the given CAEntity.
     */

    @Test
    public void testGetCAEntity() {

        final CAEntityData caEntityData = setUPData.createCAEntityData(SetUPData.SUB_CA_NAME, false);
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, SetUPData.SUB_CA_NAME, Constants.CA_NAME_PATH)).thenReturn(caEntityData);

        final CAEntityData actualcaEntityData = caPersistenceHelper.getCAEntity(SetUPData.SUB_CA_NAME);

        assertNotNull(actualcaEntityData);
        assertEquals(caEntityData.getCertificateAuthorityData().getName(), actualcaEntityData.getCertificateAuthorityData().getName());
    }

    /**
     * Test Case for checking CANotFoundException if the CAEntity is not found in the DB.
     */

    @Test(expected = CANotFoundException.class)
    public void testGetCAEntity_CA_ENTITY_NOT_FOUND() {

        final String caEntityName = null;

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, caEntityName, Constants.CA_NAME_PATH)).thenReturn(null);

        caPersistenceHelper.getCAEntity(caEntityName);

    }

    @Test(expected = EntityServiceException.class)
    public void testGetCAEntity_PersistenceException() {

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, caEntityName, Constants.CA_NAME_PATH)).thenThrow(new PersistenceException());

        caPersistenceHelper.getCAEntity(caEntityName);
    }

    @Test
    public void testStoreCertificateGenerateInfo() throws Exception {

        final CertificateGenerationInfo certificateGenerationInfo = certificateGenerationInfoSetUPData.getCertificateGenerationInfo_CAEntity();

        final CertificateGenerationInfoData certificateGenerationInfoData = createCertificateGenerationInfoData();
        Mockito.when(certificateModelMapper.toCertificateGenerationInfoData(certificateGenerationInfo)).thenReturn(certificateGenerationInfoData);

        Mockito.doNothing().when(persistenceManager).createEntity(certificateGenerationInfoData);

        caPersistenceHelper.storeCertificateGenerateInfo(certificateGenerationInfo);

        Mockito.verify(persistenceManager).createEntity(certificateGenerationInfoData);

    }

    @Test(expected = CertificateServiceException.class)
    public void testStoreCertificateGenerateInfoCertificateServiceException() throws Exception {

        final CertificateGenerationInfo certificateGenerationInfo = certificateGenerationInfoSetUPData.getCertificateGenerationInfo_CAEntity();

        final CertificateGenerationInfoData certificateGenerationInfoData = createCertificateGenerationInfoData();
        Mockito.when(certificateModelMapper.toCertificateGenerationInfoData(certificateGenerationInfo)).thenReturn(certificateGenerationInfoData);
        Mockito.doThrow(PersistenceException.class).when(persistenceManager).createEntity(certificateGenerationInfoData);

        caPersistenceHelper.storeCertificateGenerateInfo(certificateGenerationInfo);

        Mockito.verify(logger).error(ErrorMessages.INTERNAL_ERROR);

    }

    /**
     * Method to test getExternalCACertificate when CertificateDatas is null.
     * 
     * @throws PersistenceException
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void testGetExternalCACertificate() throws PersistenceException, CertificateException, IOException {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);

        Mockito.when(
                entityManager.createQuery("select c from CertificateData c where c.serialNumber =:serialnumber and c.id in(select p.id from CAEntityData"
                        + " ec inner join ec.certificateAuthorityData.certificateDatas p  WHERE ec.certificateAuthorityData.name = :name and ec.externalCA = true)")).thenReturn(query);

        final Certificate ExpectedCertificate = caPersistenceHelper.getExternalCACertificate(caEntityName, "012345");

        assertEquals(null, ExpectedCertificate);

    }

    /**
     * Method to test getExternalCACertificate when CertificateDatas have values.
     * 
     * @throws PersistenceException
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void testGetExternalCACertificate_WithCertificateDatas() throws PersistenceException, CertificateException, IOException {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);

        Mockito.when(
                entityManager.createQuery("select c from CertificateData c where c.serialNumber =:serialnumber and c.id in(select p.id from CAEntityData"
                        + " ec inner join ec.certificateAuthorityData.certificateDatas p  WHERE ec.certificateAuthorityData.name = :name and ec.externalCA = true)")).thenReturn(query);

        Mockito.when(query.getResultList()).thenReturn(CertificateDataList);

        Mockito.when(certificateModelMapper.toObjectModel(CertificateDataList)).thenReturn(certificateList);

        final Certificate ExpectedCertificate = caPersistenceHelper.getExternalCACertificate(caEntityName, "012345");

        assertNotNull(ExpectedCertificate);

        assertEquals(1234, ExpectedCertificate.getId());

    }

    /**
     * Method to test occurrence of ExternalCAAlreadyExistsException.
     * 
     * @throws CertificateFieldException
     * @throws ExternalCAAlreadyExistsException
     * @throws PersistenceException
     * @throws CertificateException
     * @throws IOException
     */
    @Test(expected = ExternalCAAlreadyExistsException.class)
    public void testStoreExtCACertificate_ExternalCAAlreadyExistsException() throws CertificateFieldException, ExternalCAAlreadyExistsException, PersistenceException, CertificateException,
            IOException {

        final String CA_NAME_PATH = "certificateAuthorityData.name";

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, caEntityName, CA_NAME_PATH)).thenReturn(setUPData.createCAEntityData(caEntityName, true));

        caPersistenceHelper.storeExtCACertificate(caEntityName, getCertificate(), false);
    }

    /**
     * Method to test occurrence of ExternalCAAlreadyExistsException.
     * 
     * @throws CertificateFieldException
     * @throws ExternalCAAlreadyExistsException
     * @throws PersistenceException
     * @throws CertificateException
     * @throws IOException
     */
    @Test(expected = ExternalCAAlreadyExistsException.class)
    public void testStoreExtCACertificate_ExternalCAAlreadyExistsException_WhenisExCATrue() throws CertificateFieldException, ExternalCAAlreadyExistsException, PersistenceException,
            CertificateException, IOException {

        final String CA_NAME_PATH = "certificateAuthorityData.name";

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, caEntityName, CA_NAME_PATH)).thenReturn(createCAEntityData(caEntityName, false));

        caPersistenceHelper.storeExtCACertificate(caEntityName, getCertificate(), false);
    }

    /**
     * Method to test storeExtCACertificate successfully.
     * 
     * @throws CertificateFieldException
     * @throws ExternalCAAlreadyExistsException
     * @throws PersistenceException
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void testStoreExtCACertificate() throws CertificateFieldException, ExternalCAAlreadyExistsException, PersistenceException, CertificateException, IOException {

        final String CA_NAME_PATH = "certificateAuthorityData.name";

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, caEntityName, CA_NAME_PATH)).thenReturn(createCAEntityData(caEntityName, true));

        Certificate certificate = getCertificate();
        Mockito.when(certificateModelMapper.fromObjectModel(certificate)).thenReturn(getCertificateData());
        Mockito.when(defaultCertExpiryNotificationDetails.prepareDefaultCertificateExpiryNotificationDetails()).thenReturn(certificateExpiryNotificationDetailsSet);
        Mockito.when(certExpiryNotificationDetailsMapper.fromAPIToModel(certificateExpiryNotificationDetailsSet, Constants.EXTERNAL_CA_CERTIFICATE_EXPIRY_NOTIFICATION_MESSAGE)).thenReturn(
                certificateExpiryNotificationDetailsDataSet);
        caPersistenceHelper.storeExtCACertificate(caEntityName, getCertificate(), false);

        Mockito.verify(persistenceManager).createEntity((CertificateData) Mockito.anyObject());

        Mockito.verify(persistenceManager).updateEntity((CAEntityData) Mockito.anyObject());

    }

    /**
     * Method to test occurrence of ExternalCAAlreadyExistsException.
     * 
     * @throws CertificateFieldException
     * @throws ExternalCAAlreadyExistsException
     * @throws PersistenceException
     * @throws CertificateException
     * @throws IOException
     */
    @Test(expected = ExternalCAAlreadyExistsException.class)
    public void testStoreExtCACertificate_WithDifferentSubjectDNs() throws CertificateFieldException, ExternalCAAlreadyExistsException, PersistenceException, CertificateException, IOException {

        final String CA_NAME_PATH = "certificateAuthorityData.name";

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, caEntityName, CA_NAME_PATH)).thenReturn(createCAEntityData(caEntityName, false));

        caPersistenceHelper.storeExtCACertificate(caEntityName, getCertificate(), false);
    }

    /**
     * Method to test occurrence of CertificateFieldException.
     * 
     * @throws CertificateFieldException
     * @throws ExternalCAAlreadyExistsException
     * @throws PersistenceException
     * @throws CertificateException
     * @throws IOException
     */
    @Test(expected = CertificateFieldException.class)
    public void testStoreExtCACertificate_CertificateFieldException() throws CertificateFieldException, ExternalCAAlreadyExistsException, PersistenceException, CertificateException, IOException {

        final String CA_NAME_PATH = "certificateAuthorityData.name";

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, caEntityName, CA_NAME_PATH)).thenReturn(createCAEntityData(caEntityName, true));

        Mockito.when(certificateModelMapper.fromObjectModel((Certificate) Mockito.anyObject())).thenThrow(new CertificateEncodingException("ErrorMessages.CERTIFICATE_ENCODING_FAILED"));

        Mockito.when(defaultCertExpiryNotificationDetails.prepareDefaultCertificateExpiryNotificationDetails()).thenReturn(certificateExpiryNotificationDetailsSet);

        Mockito.when(certExpiryNotificationDetailsMapper.fromAPIToModel(certificateExpiryNotificationDetailsSet, Constants.EXTERNAL_CA_CERTIFICATE_EXPIRY_NOTIFICATION_MESSAGE)).thenReturn(
                certificateExpiryNotificationDetailsDataSet);

        caPersistenceHelper.storeExtCACertificate(caEntityName, getCertificate(), false);

    }

    /**
     * Method to test getCertificatesForExtCA wwhen certificateDatas is empty.
     * 
     * @throws CertificateException
     * @throws PersistenceException
     * @throws IOException
     */
    @Test
    public void testGetCertificatesForExtCA() throws CertificateException, PersistenceException, IOException {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);

        Mockito.when(
                entityManager.createQuery("select c from CertificateData c where c.status in(:status) and c.id in(select p.id from CAEntityData"
                        + " ec inner join ec.certificateAuthorityData.certificateDatas p  WHERE ec.certificateAuthorityData.name = :name and ec.externalCA = true)")).thenReturn(query);

        final List<Certificate> ExpectedCertificateList = caPersistenceHelper.getCertificatesForExtCA(caEntityName, CertificateStatus.ACTIVE);

        assertEquals(null, ExpectedCertificateList);
    }

    /**
     * Method to test getCertificatesForExtCA.
     * 
     * @throws CertificateException
     * @throws PersistenceException
     * @throws IOException
     */
    @Test
    public void testGetCertificatesForExtCA_WithcertificateDatas() throws CertificateException, PersistenceException, IOException {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);

        Mockito.when(
                entityManager.createQuery("select c from CertificateData c where c.status in(:status) and c.id in(select p.id from CAEntityData"
                        + " ec inner join ec.certificateAuthorityData.certificateDatas p  WHERE ec.certificateAuthorityData.name = :name and ec.externalCA = true)")).thenReturn(query);

        Mockito.when(query.getResultList()).thenReturn(CertificateDataList);

        Mockito.when(certificateModelMapper.toObjectModel(CertificateDataList)).thenReturn(certificateList);

        final List<Certificate> ExpectedCertificateList = caPersistenceHelper.getCertificatesForExtCA(caEntityName, CertificateStatus.ACTIVE);

        assertNotNull(ExpectedCertificateList);

        assertEquals(1234, ExpectedCertificateList.get(0).getId());
    }

    /**
     * Method to test createCAEntityData.
     * 
     * @throws CertificateFieldException
     * @throws PersistenceException
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void testCreateCAEntityData() throws CertificateFieldException, PersistenceException, CertificateException, IOException {

        final CAEntityData ExpectedCAEntityData = caPersistenceHelper.createCAEntityData(caEntityName, setUPData.getX509Certificate("certificates/ENMRootCA.crt"),
                certificateExpiryNotificationDetailsSet);

        Mockito.verify(persistenceManager).createEntity(Mockito.anyObject());

        assertNotNull(ExpectedCAEntityData);

        assertEquals(true, ExpectedCAEntityData.isExternalCA());

        assertEquals(true, ExpectedCAEntityData.getCertificateAuthorityData().isRootCA());

        assertEquals("CAEntity1", ExpectedCAEntityData.getCertificateAuthorityData().getName());

    }

    /**
     * Method to test adddCRL;
     * 
     * @throws ExternalCANotFoundException
     * @throws ExternalCRLException
     * @throws PersistenceException
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void testAddCRL() throws ExternalCANotFoundException, ExternalCRLException, PersistenceException, CertificateException, IOException {
        final String CA_NAME_PATH = "certificateAuthorityData.name";

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, caEntityName, CA_NAME_PATH)).thenReturn(createCAEntityData(caEntityName, true));
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createNativeQuery(Mockito.anyString())).thenReturn(query);

        caPersistenceHelper.addCRL(caEntityName, setUPData.getExternalCRLInfo("certificates/testCA.crl"));

        Mockito.verify(persistenceManager).updateEntity((CAEntityData) Mockito.anyObject());

    }

    /**
     * Method to test adddCRL;
     * 
     * @throws ExternalCANotFoundException
     * @throws ExternalCRLException
     * @throws PersistenceException
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void testAddCRLWithOutAssociated() throws ExternalCANotFoundException, ExternalCRLException, PersistenceException, CertificateException, IOException {
        final String CA_NAME_PATH = "certificateAuthorityData.name";

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, caEntityName, CA_NAME_PATH)).thenReturn(setUPData.createCAEntityData(caEntityName, true));
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createNativeQuery(Mockito.anyString())).thenReturn(query);

        caPersistenceHelper.addCRL(caEntityName, setUPData.getExternalCRLInfo("certificates/testCA.crl"));

        Mockito.verify(persistenceManager).updateEntity((CAEntityData) Mockito.anyObject());

    }

    /**
     * Method to test adddCRL;
     * 
     * @throws ExternalCANotFoundException
     * @throws ExternalCRLException
     * @throws PersistenceException
     * @throws CertificateException
     * @throws IOException
     */
    @Test
    public void testAddCRLWithEqualSubjectDN() throws ExternalCANotFoundException, ExternalCRLException, PersistenceException, CertificateException, IOException {
        final String CA_NAME_PATH = "certificateAuthorityData.name";

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, caEntityName, CA_NAME_PATH)).thenReturn(setUPData.createCAEntityData(caEntityName, false));
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createNativeQuery(Mockito.anyString())).thenReturn(query);

        caPersistenceHelper.addCRL(caEntityName, setUPData.getExternalCRLInfo("certificates/testCA.crl"));

        Mockito.verify(persistenceManager).updateEntity((CAEntityData) Mockito.anyObject());

    }

    @Test(expected = ExternalCRLEncodedException.class)
    public void testAddCRLExternalCRLEncodedException() throws ExternalCANotFoundException, ExternalCRLException, PersistenceException, CertificateException, IOException {

        final ExternalCRLInfo crlInfo = new ExternalCRLInfo();
        caPersistenceHelper.addCRL(caEntityName, crlInfo);

    }

    @Test
    public void testAddCRLToRootCA() throws ExternalCANotFoundException, ExternalCRLException, PersistenceException, CertificateException, IOException {
        final String CA_NAME_PATH = "certificateAuthorityData.name";

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, caEntityName, CA_NAME_PATH)).thenReturn(createCAEntityDataForCRL(caEntityName, true, true));

        caPersistenceHelper.addCRL(caEntityName, setUPData.getExternalCRLInfo("certificates/testCA.crl"));
    }

    @Test
    public void testConfigCRL() throws ExternalCANotFoundException, PersistenceException {
        final String CA_NAME_PATH = "certificateAuthorityData.name";

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, caEntityName, CA_NAME_PATH)).thenReturn(createCAEntityDataForCRL(caEntityName, true, false));

        caPersistenceHelper.configCRLInfo(caEntityName, true, 0);
        Mockito.verify(persistenceManager, Mockito.times(0)).updateEntity((ExternalCRLInfoData) Mockito.anyObject());
    }

    @Test
    public void testConfigCRLWithCrlRootNotNull() throws ExternalCANotFoundException, PersistenceException {
        final String CA_NAME_PATH = "certificateAuthorityData.name";

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, caEntityName, CA_NAME_PATH)).thenReturn(createCAEntityDataForCRL(caEntityName, false, false));

        caPersistenceHelper.configCRLInfo(caEntityName, true, 0);
        Mockito.verify(persistenceManager, Mockito.times(2)).updateEntity((ExternalCRLInfoData) Mockito.anyObject());
    }

    @Test(expected = ExternalCANotFoundException.class)
    public void testConfigCRLExternalCANotFoundException() throws ExternalCANotFoundException, PersistenceException {
        final String CA_NAME_PATH = "certificateAuthorityData.name";

        final CAEntityData caentityData = createCAEntityDataForCRL(caEntityName, false, false);
        caentityData.setExternalCA(false);
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, caEntityName, CA_NAME_PATH)).thenReturn(caentityData);
        caPersistenceHelper.configCRLInfo(caEntityName, true, 0);
    }

    /**
     * Method to test getTrustProfileNamesUsingExtCA.
     */
    @SuppressWarnings("unchecked")
    @Test
    public void testGetTrustProfileNamesUsingExtCA() {

        Mockito.when(persistenceManager.findEntitiesByAttributes(Mockito.anyString(), Mockito.anyMap())).thenReturn(trustProfileDatas);

        final List<String> ExpectedProfileNames = caPersistenceHelper.getTrustProfileNamesUsingExtCA(createCAEntityData(caEntityName, true));

        assertNotNull(ExpectedProfileNames);

        assertEquals(1, ExpectedProfileNames.size());

        assertEquals("ProfileName", ExpectedProfileNames.get(0));
    }

    /**
     * Method to test occurrence of ExternalCANotFoundException.
     * 
     * @throws ExternalCANotFoundException
     * @throws ExternalCRLException
     * @throws PersistenceException
     * @throws CertificateException
     * @throws IOException
     */
    @Test(expected = ExternalCANotFoundException.class)
    public void testAddCRL_ExternalCANotFoundException() throws ExternalCANotFoundException, ExternalCRLException, PersistenceException, CertificateException, IOException {

        caPersistenceHelper.addCRL(caEntityName, setUPData.getExternalCRLInfo("certificates/testCA.crl"));
    }

    /**
     * Method to test occurrence of ExternalCANotFoundException.
     * 
     * @throws ExternalCANotFoundException
     * @throws PersistenceException
     */

    @Test(expected = ExternalCANotFoundException.class)
    public void testConfigCRL_ExternalCANotFoundException() throws ExternalCANotFoundException, PersistenceException {

        caPersistenceHelper.configCRLInfo(caEntityName, true, 0);
    }

    /**
     * Method to test occurrence of ExternalCANotFoundException.
     */
    @Test(expected = ExternalCANotFoundException.class)
    public void testGetExternalCRLInfoForExtCA_ExternalCANotFoundException() {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);

        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);

        caPersistenceHelper.getExternalCRLInfoForExtCA(caEntityName);
    }

    /**
     * Method to test occurrence of ExternalCRLNotFoundException.
     */
    @Test(expected = ExternalCRLNotFoundException.class)
    public void testGetExternalCRLInfoForExtCA_ExternalCRLNotFoundException_WhenCrlSizZero() {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);

        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);

        Mockito.when(query.getResultList()).thenReturn(CAEntityDataList);

        caPersistenceHelper.getExternalCRLInfoForExtCA(caEntityName);
    }

    /**
     * Method to test getExternalCRLInfoForExtCA.
     */
    @Test
    public void testGetExternalCRLInfoForExtCA() {

        final List<CAEntityData> CAEntityDataListSuccess = new ArrayList<CAEntityData>();
        CAEntityDataListSuccess.add(createCAEntityData(caEntityName, false));

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);

        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);

        Mockito.when(query.getResultList()).thenReturn(CAEntityDataListSuccess);

        caPersistenceHelper.getExternalCRLInfoForExtCA(caEntityName);
    }

    @Test(expected = InvalidOperationException.class)
    public void testGetLatestCertificateGenerationInfo() {
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(persistenceManager.getEntityManager().createQuery(CERTIFICATE_GENERATION_INFO_QUERY)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(certificateGenerationInfoDataList);

        CertificateGenerationInfoData certificateGenerationInfoData = caPersistenceHelper.getLatestCertificateGenerationInfo(caEntityName);
        Assert.assertEquals(certificateGenerationInfoData, null);

    }

    @Test(expected = InvalidOperationException.class)
    public void testGetLatestCertificateGenerationInfoisNull() {
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(persistenceManager.getEntityManager().createQuery(CERTIFICATE_GENERATION_INFO_QUERY)).thenReturn(query);

        Mockito.when(query.getResultList()).thenReturn(null);
        CertificateGenerationInfoData certificateGenerationInfoData = caPersistenceHelper.getLatestCertificateGenerationInfo(caEntityName);
        Assert.assertEquals(certificateGenerationInfoData, null);
    }

    @Test
    public void testGetLatestCertificateGenerationInfoNotEmpty() {
        certificateGenerationInfoDataList.add(certificateGenerationInfoData);

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(persistenceManager.getEntityManager().createQuery(CERTIFICATE_GENERATION_INFO_QUERY)).thenReturn(query);

        Mockito.when(query.getResultList()).thenReturn(certificateGenerationInfoDataList);

        CertificateGenerationInfoData certificateGenerationInfoData = caPersistenceHelper.getLatestCertificateGenerationInfo(caEntityName);
        Assert.assertNotNull(certificateGenerationInfoData);

    }

    private CertificateGenerationInfoData createCertificateGenerationInfoData() {

        final CertificateGenerationInfoData certificateGenerationInfoData = new CertificateGenerationInfoData();

        certificateGenerationInfoData.setId(1);
        certificateGenerationInfoData.setCertificateVersion(CertificateVersion.V3);
        certificateGenerationInfoData.setSubjectUniqueIdentifier(true);
        certificateGenerationInfoData.setIssuerUniqueIdentifier(true);
        return certificateGenerationInfoData;

    }

    /**
     * Mock the issuerCAEntityData and CertificateData.
     * 
     * @param certificate
     * @return CertificateData
     * 
     * @throws CertificateException
     * @throws CertificateEncodingException
     * @throws IOException
     */
    private static CertificateData mockCertificateData(final Certificate certificate) throws CertificateException, CertificateEncodingException, IOException {

        final CAEntityData issuerCAEntityData = setUPData.createCAEntityData(SetUPData.ROOT_CA_NAME, false);
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, SetUPData.ROOT_CA_NAME, Constants.CA_NAME_PATH)).thenReturn(issuerCAEntityData);

        final CertificateData certificateData = setUPData.createCertificateData("12345");
        Mockito.when(certificateModelMapper.fromObjectModel(certificate)).thenReturn(certificateData);

        return certificateData;
    }

    /**
     * Method to get CertificateData.
     * 
     * @return CertificateData.
     */
    private static CertificateData getCertificateData() {
        final CertificateData certificateData = new CertificateData();
        certificateData.setId(1234);
        CAEntityData caEntityData = new CAEntityData();
        caEntityData.setId(1);
        certificateData.setIssuerCA(caEntityData);
        return certificateData;

    }

    /**
     * Method to get Certificate.
     * 
     * @return Certificate.
     * @throws IOException
     * @throws CertificateException
     */
    private static Certificate getCertificate() throws CertificateException, IOException {
        final Certificate certificate = new Certificate();
        certificate.setId(1234);
        certificate.setX509Certificate(setUPData.getX509Certificate("certificates/ENMRootCA.crt"));
        return certificate;

    }

    /**
     * create CAEntity Data.
     * 
     * @param caEntityName
     *            return CAEntityData
     */
    public static CAEntityData createCAEntityData(final String caEntityName, final boolean isRootCA) {
        final CAEntityData caEntityData = new CAEntityData();
        final Set<CAEntityData> associated = new HashSet<CAEntityData>();
        final CAEntityData CAEntityData = setUPData.createCAEntityData(caEntityName, true);
        associated.add(CAEntityData);
        caEntityData.setAssociated(associated);
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setName(caEntityName);
        certificateAuthorityData.setRootCA(isRootCA);
        final Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
        certificateDatas.add(getCertificateData());
        certificateAuthorityData.setCertificateDatas(certificateDatas);
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        if (isRootCA) {
            caEntityData.setExternalCA(true);
            certificateAuthorityData.setSubjectDN("CN=MyRoot");

        } else {
            caEntityData.setExternalCA(false);
            certificateAuthorityData.setSubjectDN("CN=NotMyRoot");
            final ExternalCRLInfoData externalCrlInfoData = new ExternalCRLInfoData();
            externalCrlInfoData.setId(1234);
            certificateAuthorityData.setExternalCrlInfoData(externalCrlInfoData);

        }
        return caEntityData;
    }

    public static CAEntityData createCAEntityDataForCRL(final String caEntityName, final boolean isRootCA, final boolean addCRLToRoot) {
        final CAEntityData caEntityData = new CAEntityData();
        final Set<CAEntityData> associated = new HashSet<CAEntityData>();

        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setName(caEntityName);
        certificateAuthorityData.setRootCA(isRootCA);
        final Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
        certificateDatas.add(getCertificateData());
        certificateAuthorityData.setCertificateDatas(certificateDatas);
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        if (isRootCA) {
            caEntityData.setExternalCA(true);
            certificateAuthorityData.setSubjectDN("CN=MyRoot");
            if (addCRLToRoot) {
                final ExternalCRLInfoData externalCrlInfoData = new ExternalCRLInfoData();
                externalCrlInfoData.setId(1234);
                certificateAuthorityData.setExternalCrlInfoData(externalCrlInfoData);
            }

        } else {
            caEntityData.setExternalCA(true);
            certificateAuthorityData.setSubjectDN("CN=NotMyRoot");
            final ExternalCRLInfoData externalCrlInfoData = new ExternalCRLInfoData();
            externalCrlInfoData.setId(1234);
            certificateAuthorityData.setExternalCrlInfoData(externalCrlInfoData);

            final CAEntityData CAEntityData = setUPData.createCAEntityData(caEntityName, true);
            CAEntityData.setCertificateAuthorityData(certificateAuthorityData);
            associated.add(CAEntityData);
            caEntityData.setAssociated(associated);
        }
        return caEntityData;
    }

    @Test
    public void testUpdateCertificateGenerateInfoWithCSR() {

        final byte[] certificateRequest = new byte[] { 1 };
        long id = 1;
        Mockito.when(certificateGenerationInfo.getId()).thenReturn(id);
        Mockito.when(persistenceManager.findEntity(CertificateGenerationInfoData.class, id)).thenReturn(certificateGenerationInfoData);

        caPersistenceHelper.updateCertificateGenerateInfoWithCSR(certificateGenerationInfo, certificateRequest);

        Mockito.verify(persistenceManager).updateEntity(certificateGenerationInfoData);
    }

    @Test(expected = CertificateServiceException.class)
    public void testUpdateCertificateGenerateInfoWithCSR_PersistenceException() {
        final byte[] certificateRequest = new byte[] { 1 };
        long id = 1;
        Mockito.when(certificateGenerationInfo.getId()).thenReturn(id);
        Mockito.when(persistenceManager.findEntity(CertificateGenerationInfoData.class, id)).thenReturn(certificateGenerationInfoData);

        Mockito.when(persistenceManager.updateEntity(certificateGenerationInfoData)).thenThrow(new PersistenceException());
        caPersistenceHelper.updateCertificateGenerateInfoWithCSR(certificateGenerationInfo, certificateRequest);

    }

    @Test
    public void testUpdateIsIssuerExternalCAFlag() throws CertificateServiceException {
        caPersistenceHelper.updateIsIssuerExternalCAFlag(createCAEntityData(caEntityName, false), true);
    }

    @Test
    public void testUpdateSetIssuerCertificate_Revoked() throws Exception {

        CertificateData certificateData = setUPData.createCertificateData(CERTIFICATE_ID);
        certificateData.setCertificate(setUPData.getX509Certificate(FILE_PATH).getEncoded());
        certificateData.setStatus(3);

        CertificateData issuerCertificateData = setUPData.createCertificateData(CERTIFICATE_ID);
        issuerCertificateData.setCertificate(setUPData.getX509Certificate(FILE_PATH).getEncoded());
        issuerCertificateData.setStatus(3);

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);

        caPersistenceHelper.updateIssuerCAandCertificate(certificateData, caEntityData, issuerCertificateData);
    }

    @Test
    public void testUpdateSetIssuerCertificate_Expired() throws Exception {

        CertificateData certificateData = setUPData.createCertificateData(CERTIFICATE_ID);
        certificateData.setCertificate(setUPData.getX509Certificate(FILE_PATH).getEncoded());
        certificateData.setStatus(2);

        CertificateData issuerCertificateData = setUPData.createCertificateData(CERTIFICATE_ID);
        issuerCertificateData.setCertificate(setUPData.getX509Certificate(FILE_PATH).getEncoded());
        issuerCertificateData.setStatus(2);

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);

        caPersistenceHelper.updateIssuerCAandCertificate(certificateData, caEntityData, issuerCertificateData);
    }

}
