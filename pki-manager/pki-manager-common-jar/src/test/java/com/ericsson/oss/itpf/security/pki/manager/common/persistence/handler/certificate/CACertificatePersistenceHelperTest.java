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

/** @author  emcgtom
 * 
 */

package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate;

import static org.junit.Assert.*;
import static org.mockito.Mockito.times;

import java.io.IOException;
import java.io.InputStream;
import java.security.cert.*;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.persistence.*;
import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.helpers.DefaultCertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.CertificateExpiryNotificationDetailsMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.externalCA.ExternalCRLMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.certificate.CertificateModelMapperV1;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidOperationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ca.ExternalCANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.NotificationSeverity;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

@RunWith(MockitoJUnitRunner.class)
public class CACertificatePersistenceHelperTest {

    @InjectMocks
    CACertificatePersistenceHelper cACertificatePersistenceHelper;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    EntityManager entityManager;

    @Mock
    Query query;

    @Mock
    DNBasedCertificateIdentifier dNBasedCertificateIdentifier;

    @Mock
    CertificateModelMapper certificateModelMapper;

    @Mock
    CertificateModelMapperV1 certificateModelMapperV1;

    @Mock
    CertificateGenerationInfoData certGenInfoData;

    @Mock
    X509Certificate x509Certificate;

    @Mock
    X509CRL x509CRL;

    @Mock
    X509CRLHolder x509CRLHolder;

    @Mock
    ExternalCRLInfoData externalCrlInfoData;

    @Mock
    CertificateAuthorityData certificateAuthorityData;

    @Mock
    CertificateData certificateData;

    @Mock
    CertificateData issuerCertificateData;

    @Mock
    Subject subject;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    CAEntityDynamicQueryBuilder caEntityDynamicQueryBuilder;

    @Mock
    DNBasedCertificateIdentifier dNBasedIdentifier;

    @Mock
    Map<String, Object> parameters;

    @Mock
    Logger logger;

    @Mock
    ExternalCRLMapper crlMapper;

    @Mock
    ExternalCRLInfo externalCRLInfo;

    @Mock
    ExtCACertificatePersistanceHandler extCACertificatePersistanceHandler;

    @Mock
    DefaultCertificateExpiryNotificationDetails defaultCertExpiryNotificationDetails;

    @Mock
    CertificateExpiryNotificationDetailsMapper certExpiryNotificationDetailsMapper;

    SetUPData setUPData = new SetUPData();
    private CertificateGenerationInfo certGenInfo;
    private Certificate certificate;
    private List<Certificate> certificates;
    private static CertificateAuthority certificateAuthority;
    private CAEntityData caEntityData;
    private List<CAEntityData> caEntityDataList;
    private byte[] certificateRequest;
    private Date validation;
    private CertificateRequestData certificateRequestData;
    X509Certificate x509Certificate1;
    Set<CertificateData> certificateDatas;
    List<CertificateData> certificateDatasList;

    private SubjectAltName subjectAltName;

    private static SetUPData setupData;
    private final static String entityName = "SubCA";
    private static CertificateExpiryNotificationDetails certificateExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
    private static Set<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();
    private static CertificateExpiryNotificationDetailsData certificateExpiryNotificationDetailsData = new CertificateExpiryNotificationDetailsData();
    private static Set<CertificateExpiryNotificationDetailsData> certificateExpiryNotificationDetailsDataSet = new HashSet<CertificateExpiryNotificationDetailsData>();
    private String qlString;
    private static final String FETCH_ALL_CA_NAME_AND_SERIAL_NO_NATIVE_QUERY = "SELECT ca.name, c.serial_number FROM caentity ca JOIN ca_certificate cc ON ca.id = cc.ca_id JOIN certificate c ON cc.certificate_id = c.id where ca.is_external_ca = 'false'";
    private static final String CAENTITY_CERTIFICATES_BY_CANAME_AND_STATUS = "select c from CertificateData c where c.id in(select p.id from CAEntityData ec inner join ec.certificateAuthorityData.certificateDatas p  WHERE ec.certificateAuthorityData.name = :name and p.status in(:status) and ec.externalCA = false) ORDER BY c.id DESC";
    private static final String QUERY_FOR_FETCH_LATEST_CSR = "select cgf from CertificateGenerationInfoData cgf where cgf.forExternalCA = true and cgf.cAEntityInfo in"
            + " ( select ec.id from CAEntityData ec where ec.certificateAuthorityData.name = :name) ORDER BY cgf.id DESC";
    private static final String SUBCA_CERTIFICATES_BY_ISSUER_CERTIFICATE_AND_STATUS = "select c from CertificateData c where c.issuerCertificate.id = :issuerCertificate and c.status in(:status) ORDER BY c.id DESC";
    private static final String TRUST_PROFILE_QUERY = "select t from TrustProfileData t join t.externalCAs c where t.active in(:is_active) and c.id=:externalca_id";
    private String string = "10101";
    private static final String updatedCRL = "updateURL";
    private static final String subjectDN = "CN=ENMSubCA";
    private static final String CA_NAMES_BY_STATUS = "SELECT ca.certificateAuthorityData.name FROM CAEntityData ca WHERE ca.externalCA=false AND ca.certificateAuthorityData.status in (:status)";

    @BeforeClass
    public static void setup() {
        setupData = new SetUPData();
    }

    @Before
    public void setUp() throws CRLException, CertificateException, IOException, DatatypeConfigurationException {

        certificateDatas = new HashSet<>();
        certificateDatasList = new ArrayList<CertificateData>();

        caEntityData = new CAEntityData();
        caEntityData.setId(10111);
        caEntityData.setExternalCA(true);
        certificateAuthorityData.setExternalCrlInfoData(externalCrlInfoData);
        certificateAuthorityData.setRootCA(true);
        certificateAuthorityData.setIssuerExternalCA(true);
        certificateAuthorityData.setSubjectDN("CN=ENMSubCA");
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        certificateExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.CRITICAL);
        certificateExpiryNotificationDetails.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration(Constants.DEFAULT_PERIOD_BEFORE_EXPIRY_CRITICAL));
        certificateExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration(Constants.DEFAULT_FREQUENCY_OF_NOTIFICATION_CRITICAL));
        certificateExpiryNotificationDetailsSet.add(certificateExpiryNotificationDetails);
        certificateExpiryNotificationDetailsData.setNotificationSeverity((NotificationSeverity.CRITICAL).getId());
        certificateExpiryNotificationDetailsData.setPeriodBeforeExpiry((DatatypeFactory.newInstance().newDuration(Constants.DEFAULT_PERIOD_BEFORE_EXPIRY_CRITICAL)).getDays());
        certificateExpiryNotificationDetailsData.setFrequencyOfNotification((DatatypeFactory.newInstance().newDuration(Constants.DEFAULT_FREQUENCY_OF_NOTIFICATION_CRITICAL)).getDays());
        certificateExpiryNotificationDetailsData.setNotificationMessage(Constants.EXTERNAL_CA_CERTIFICATE_EXPIRY_NOTIFICATION_MESSAGE);
        certificateExpiryNotificationDetailsDataSet.add(certificateExpiryNotificationDetailsData);

        certificateAuthority = new CertificateAuthority();
        certificateAuthority.setId(10111);
        certificateAuthority.setName("subCA");

        final Date revokedTime = new Date();
        final Date notBefore = new Date();
        final Date notAfter = new Date();

        subject = new Subject();
        subjectAltName = new SubjectAltName();

        certificate = new Certificate();
        certificate.setId(101);
        certificate.setIssuedTime(new Date());
        certificate.setSerialNumber("10101");
        certificate.setStatus(CertificateStatus.ACTIVE);
        certificate.setIssuer(certificateAuthority);
        certificate.setRevokedTime(revokedTime);
        certificate.setNotBefore(notBefore);
        certificate.setNotAfter(notAfter);
        certificate.setSubject(subject);
        certificate.setSubjectAltName(subjectAltName);

        x509Certificate1 = setUPData.getX509Certificate("certificates/ENMRootCA.crt");
        certificate.setX509Certificate(x509Certificate1);

        certificates = new ArrayList<Certificate>();

        certificates.add(certificate);

        certGenInfo = new CertificateGenerationInfo();
        certGenInfo.setId(101);
        certGenInfo.setCAEntityInfo(certificateAuthority);
        certGenInfo.setGeneratedCertificate(certificate);

        certificateDatas.add(certificateData);
        certificateDatasList.add(certificateData);

        caEntityDataList = new ArrayList<CAEntityData>();
        caEntityDataList.add(caEntityData);
    }

    @Test
    public void testStoreCertificate() throws CertificateFieldException, CertificateException, PersistenceException, IOException {
        qlString = CAENTITY_CERTIFICATES_BY_CANAME_AND_STATUS;

        CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.getCertificateDatas();
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, entityName, "certificateAuthorityData.name")).thenReturn(caEntityData);
        Mockito.when(persistenceManager.findEntity(CertificateGenerationInfoData.class, certGenInfo.getId())).thenReturn(certGenInfoData);
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(qlString)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(certificateDatasList);
        Mockito.when(certificateModelMapper.fromObjectModel(certificate)).thenReturn(certificateData);
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, certificate.getIssuer().getName(), Constants.CA_NAME_PATH)).thenReturn(caEntityData);

        cACertificatePersistenceHelper.storeCertificate(entityName, certGenInfo, certificate);

        Mockito.verify(persistenceManager).createEntity(certificateData);
        Mockito.verify(persistenceManager).updateEntity(certGenInfoData);
        Mockito.verify(persistenceManager).refresh(caEntityData);
        Mockito.verify(persistenceManager, times(2)).updateEntity(caEntityData);
    }

    @Test
    public void testGetCertificates() throws CertificateException, PersistenceException, IOException {
        qlString = CAENTITY_CERTIFICATES_BY_CANAME_AND_STATUS;

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(qlString)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(certificateDatasList);
        Mockito.when(certificateModelMapperV1.toApi(certificateDatasList, MappingDepth.LEVEL_1)).thenReturn(certificates);
        assertEquals(certificates, cACertificatePersistenceHelper.getCertificates(entityName, MappingDepth.LEVEL_1, CertificateStatus.ACTIVE));
    }

    @Test
    public void testGetCertificateDatas() {

        qlString = CAENTITY_CERTIFICATES_BY_CANAME_AND_STATUS;
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(qlString)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(certificateDatasList);
        assertEquals(certificateDatasList, cACertificatePersistenceHelper.getCertificateDatas(entityName, CertificateStatus.ACTIVE));
    }

    @Test
    public void testGetActiveInActiveCertificateDatas() {
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(SUBCA_CERTIFICATES_BY_ISSUER_CERTIFICATE_AND_STATUS)).thenReturn(query);
        assertNull(cACertificatePersistenceHelper.getActiveInActiveCertificateDatas(certificate));
    }

    @Test
    public void testGetActiveCertificate() throws CertificateException, PersistenceException, IOException {

        List<CertificateData> certificateDatasList = new ArrayList<>();
        CertificateData certData = new CertificateData();

        certData.setCertificate(x509Certificate1.getEncoded());
        certificateDatasList.add(certData);

        qlString = CAENTITY_CERTIFICATES_BY_CANAME_AND_STATUS;
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(qlString)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(certificateDatasList);

        assertNotNull(cACertificatePersistenceHelper.getActiveCertificate(entityName));
    }

    @Test
    public void testGetCAEntity() {

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, entityName, Constants.CA_NAME_PATH)).thenReturn(caEntityData);
        assertEquals(caEntityData, cACertificatePersistenceHelper.getCAEntity(entityName));
    }

    @Test(expected = CANotFoundException.class)
    public void testGetCAEntityCANotFoundException() {
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, entityName, Constants.CA_NAME_PATH)).thenReturn(null);
        cACertificatePersistenceHelper.getCAEntity(entityName);
    }

    @Test
    public void testGetCAEntityWithSubjectDN() {
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, entityName, certificateAuthority.getName())).thenReturn(caEntityData);
        assertEquals(caEntityData, cACertificatePersistenceHelper.getCAEntity(entityName, certificateAuthority.getName()));
    }

    @Test(expected = CANotFoundException.class)
    public void testGetCAEntityWithOutSubject() {
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, entityName, certificateAuthority.getName())).thenReturn(null);

        cACertificatePersistenceHelper.getCAEntity(entityName, certificateAuthority.getName());
    }

    @Test
    public void testGetExternalCACertificate() throws PersistenceException, CertificateException, IOException {
        qlString = "select c from CertificateData c where c.serialNumber =:serialnumber and c.id in(select p.id from CAEntityData"
                + " ec inner join ec.certificateAuthorityData.certificateDatas p  WHERE ec.certificateAuthorityData.name = :name and ec.externalCA = true)";
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(qlString)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(certificateDatasList);
        Mockito.when(certificateModelMapper.toObjectModel(certificateDatasList)).thenReturn(certificates);

        assertEquals(certificate, cACertificatePersistenceHelper.getExternalCACertificate(entityName, certificate.getSerialNumber()));
    }

    @Test
    public void testGetAllCANameAndSerialNumber() {
        final List<CACertificateIdentifier> caCertificateIdentifierList = new ArrayList<CACertificateIdentifier>();
        List<Object[]> results = new ArrayList<Object[]>();

        Object[] objectArray = new Object[2];
        objectArray[1] = string;
        results.add(objectArray);

        final CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();
        caCertificateIdentifier.setCaName((String) objectArray[0]);
        caCertificateIdentifier.setCerficateSerialNumber((String) objectArray[1]);
        caCertificateIdentifierList.add(caCertificateIdentifier);

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createNativeQuery(FETCH_ALL_CA_NAME_AND_SERIAL_NO_NATIVE_QUERY)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(results);

        assertEquals(caCertificateIdentifierList, cACertificatePersistenceHelper.getAllCANameAndSerialNumber());
    }

    @Test
    public void testGetCAEntityData() {
        qlString = " select ec from CAEntityData ec " + " inner join ec.certificateAuthorityData.certificateDatas certs  " + " WHERE "
                + " ec.certificateAuthorityData.name = :name AND certs.serialNumber = :serialnumber ";
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(qlString)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(caEntityDataList);
        assertEquals(caEntityData, cACertificatePersistenceHelper.getCAEntityData(entityName, certificate.getSerialNumber()));

    }

    @Test
    public void testGetCAEntitiesCount() {
        final StringBuilder qlString = new StringBuilder();
        final Long count = (long) 0;
        qlString.append(" select count(*) from CAEntityData ced ");
        Mockito.when(caEntityDynamicQueryBuilder.where(dNBasedIdentifier, qlString)).thenReturn(parameters);
        Mockito.when(persistenceManager.findEntitiesCountByAttributes(qlString.toString(), parameters)).thenReturn(count);
        assertEquals(count, cACertificatePersistenceHelper.getCAEntitiesCount(dNBasedCertificateIdentifier));
    }

    @Test
    public void testStoreCertificateGenerateInfo() {

        Mockito.when(certificateModelMapper.toCertificateGenerationInfoData(certGenInfo)).thenReturn(certGenInfoData);
        cACertificatePersistenceHelper.storeCertificateGenerateInfo(certGenInfo);
        Mockito.verify(persistenceManager).createEntity(certGenInfoData);
    }

    @Test(expected = CertificateServiceException.class)
    public void testStoreCertificateGenerateInfoCertificateServiceException() {

        Mockito.when(certificateModelMapper.toCertificateGenerationInfoData(certGenInfo)).thenReturn(certGenInfoData);
        Mockito.doThrow(new PersistenceException()).when(persistenceManager).createEntity(certGenInfoData);
        cACertificatePersistenceHelper.storeCertificateGenerateInfo(certGenInfo);
    }

    @Test
    public void testUpdateCertificateGenerateInfoWithCSR() {
        Mockito.when(persistenceManager.findEntity(CertificateGenerationInfoData.class, certGenInfo.getId())).thenReturn(certGenInfoData);
        cACertificatePersistenceHelper.updateCertificateGenerateInfoWithCSR(certGenInfo, certificateRequest);
        Mockito.verify(persistenceManager).updateEntity(certGenInfoData);
    }

    @Test
    public void testStoreExtCACertificate() throws CertificateEncodingException {

        Mockito.when(certificateModelMapper.fromObjectModel(certificate)).thenReturn(certificateData);
        Mockito.when(defaultCertExpiryNotificationDetails.prepareDefaultCertificateExpiryNotificationDetails()).thenReturn(certificateExpiryNotificationDetailsSet);
        Mockito.when(certExpiryNotificationDetailsMapper.fromAPIToModel(certificateExpiryNotificationDetailsSet, Constants.EXTERNAL_CA_CERTIFICATE_EXPIRY_NOTIFICATION_MESSAGE)).thenReturn(
                certificateExpiryNotificationDetailsDataSet);
        Mockito.doNothing().when(extCACertificatePersistanceHandler).setIssuerToExtCertificate(caEntityData, certificateData, true);

        cACertificatePersistenceHelper.storeExtCACertificate("Root", certificate, true);

        Mockito.verify(persistenceManager).createEntity(certificateData);
    }

    @Test
    public void testStoreExtCACertificateWithGivenCAEntity() throws CertificateEncodingException {

        certificateAuthorityData.setCertificateDatas(certificateDatas);
        certificateAuthorityData.setSubjectDN("CN=MyRoot");
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, "Root", "certificateAuthorityData.name")).thenReturn(caEntityData);
        Mockito.when(certificateModelMapper.fromObjectModel(certificate)).thenReturn(certificateData);
        Mockito.doNothing().when(extCACertificatePersistanceHandler).setIssuerToExtCertificate(caEntityData, certificateData, true);
        cACertificatePersistenceHelper.storeExtCACertificate("Root", certificate, true);

        Mockito.verify(persistenceManager).createEntity(certificateData);
    }

    @Test
    public void testGetCertificatesForExtCA() throws CertificateException, PersistenceException, IOException {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(
                entityManager.createQuery("select c from CertificateData c where c.status in(:status) and c.id in(select p.id from CAEntityData"
                        + " ec inner join ec.certificateAuthorityData.certificateDatas p  WHERE ec.certificateAuthorityData.name = :name and ec.externalCA = true)")).thenReturn(query);

        Mockito.when(query.getResultList()).thenReturn(certificateDatasList);
        Mockito.when(certificateModelMapper.toObjectModel(certificateDatasList)).thenReturn(certificates);

        assertEquals(certificates, cACertificatePersistenceHelper.getCertificatesForExtCA(entityName, CertificateStatus.ACTIVE));
    }

    @Test
    public void testAddCRL() throws CRLException, CertificateException, IOException {

        final Set<CAEntityData> associated = new HashSet<CAEntityData>();
        final ExternalCRLInfo crl = new ExternalCRLInfo();
        final CAEntityData caEntityData2 = new CAEntityData();
        final CAEntityData caEntityData = new CAEntityData();

        crl.setX509CRL(getCRL("certificates/testCA.crl"));
        crl.setNextUpdate(new Date());
        crl.setAutoUpdate(true);
        crl.setAutoUpdateCheckTimer(1);

        caEntityData.setExternalCA(true);
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        final CertificateAuthorityData certificateAuthorityData2 = new CertificateAuthorityData();

        certificateAuthorityData.setExternalCrlInfoData(externalCrlInfoData);
        certificateAuthorityData2.setExternalCrlInfoData(externalCrlInfoData);
        certificateAuthorityData2.setSubjectDN(crl.getX509CRL().retrieveCRL().getIssuerX500Principal().getName());
        caEntityData2.setCertificateAuthorityData(certificateAuthorityData2);
        associated.add(caEntityData2);

        certificateAuthorityData.setSubjectDN(subjectDN);
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        caEntityData.setAssociated(associated);

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, entityName, "certificateAuthorityData.name")).thenReturn(caEntityData);
        cACertificatePersistenceHelper.addCRL(entityName, crl);
    }

    @Test
    public void testAddCRLWithOutExternalCA() throws CRLException, CertificateException, IOException {

        final Set<CAEntityData> associated = new HashSet<CAEntityData>();
        final ExternalCRLInfo crl = new ExternalCRLInfo();
        final CAEntityData caEntityData2 = new CAEntityData();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        final CertificateAuthorityData certificateAuthorityData2 = new CertificateAuthorityData();

        certificateAuthorityData2.setExternalCrlInfoData(externalCrlInfoData);
        certificateAuthorityData2.setSubjectDN(subjectDN);
        caEntityData2.setCertificateAuthorityData(certificateAuthorityData2);
        associated.add(caEntityData2);

        crl.setX509CRL(getCRL("certificates/testCA.crl"));
        crl.setNextUpdate(new Date());

        certificateAuthorityData.setSubjectDN(crl.getX509CRL().retrieveCRL().getIssuerX500Principal().getName());
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        caEntityData.setAssociated(associated);

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, entityName, "certificateAuthorityData.name")).thenReturn(caEntityData);
        cACertificatePersistenceHelper.addCRL(entityName, crl);
    }

    @Test
    public void testAddCRLWithIssuerEqualsSubject() throws CRLException, CertificateException, IOException {

        final ExternalCRLInfo crl = new ExternalCRLInfo();
        crl.setX509CRL(getCRL("certificates/testCA.crl"));
        crl.setUpdateURL(updatedCRL);
        crl.setAutoUpdate(true);
        crl.setAutoUpdateCheckTimer(1);

        final ExternalCRLInfoData externalCrlInfoData = new ExternalCRLInfoData();
        externalCrlInfoData.setAutoUpdate(true);
        externalCrlInfoData.setAutoUpdateCheckTimer(1000);

        final CertificateAuthorityData certAuthData = new CertificateAuthorityData();
        certAuthData.setSubjectDN(crl.getX509CRL().retrieveCRL().getIssuerX500Principal().getName());
        certAuthData.setExternalCrlInfoData(externalCrlInfoData);
        final CAEntityData caEntityData = new CAEntityData();
        caEntityData.setCertificateAuthorityData(certAuthData);
        caEntityData.setExternalCA(true);

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, entityName, "certificateAuthorityData.name")).thenReturn(caEntityData);

        cACertificatePersistenceHelper.addCRL(entityName, crl);
    }

    @Test
    public void testAddCRLWithIssuerDifferantSubject() throws CRLException, CertificateException, IOException {

        final ExternalCRLInfo crl = new ExternalCRLInfo();
        crl.setX509CRL(getCRL("certificates/testCA.crl"));
        crl.setUpdateURL(updatedCRL);
        crl.setAutoUpdate(true);
        crl.setAutoUpdateCheckTimer(1);

        final ExternalCRLInfoData externalCrlInfoData = new ExternalCRLInfoData();
        externalCrlInfoData.setAutoUpdate(true);
        externalCrlInfoData.setAutoUpdateCheckTimer(1000);

        final CertificateAuthorityData certAuthData = new CertificateAuthorityData();
        certAuthData.setSubjectDN(subjectDN);
        certAuthData.setExternalCrlInfoData(externalCrlInfoData);
        final CAEntityData caEntityData = new CAEntityData();
        caEntityData.setCertificateAuthorityData(certAuthData);
        caEntityData.setExternalCA(true);

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, entityName, "certificateAuthorityData.name")).thenReturn(caEntityData);

        cACertificatePersistenceHelper.addCRL(entityName, crl);
    }

    @Test
    public void testAddCRLWithIssuerEqualsSubjectAndNotAutoUpdate() throws CRLException, CertificateException, IOException {

        final ExternalCRLInfo crl = new ExternalCRLInfo();
        crl.setX509CRL(getCRL("certificates/testCA.crl"));
        crl.setUpdateURL(updatedCRL);
        crl.setAutoUpdate(true);
        crl.setAutoUpdateCheckTimer(1);

        final ExternalCRLInfoData externalCrlInfoData = new ExternalCRLInfoData();
        externalCrlInfoData.setAutoUpdate(false);

        final CertificateAuthorityData certAuthData = new CertificateAuthorityData();
        certAuthData.setSubjectDN(crl.getX509CRL().retrieveCRL().getIssuerX500Principal().getName());
        certAuthData.setExternalCrlInfoData(externalCrlInfoData);
        final CAEntityData caEntityData = new CAEntityData();
        caEntityData.setCertificateAuthorityData(certAuthData);
        caEntityData.setExternalCA(true);

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, entityName, "certificateAuthorityData.name")).thenReturn(caEntityData);

        cACertificatePersistenceHelper.addCRL(entityName, crl);
    }

    private X509CRLHolder getCRL(final String filename) throws IOException, CertificateException {
        final InputStream inputStream = Thread.currentThread().getContextClassLoader().getResourceAsStream(filename);
        final CertificateFactory certificateFactory = CertificateFactory.getInstance("X.509");
        try {
            final X509CRL crl = (X509CRL) certificateFactory.generateCRL(inputStream);
            return new X509CRLHolder(crl.getEncoded());
        } catch (final CRLException e) {
            e.printStackTrace();
        }
        return null;
    }

    @Test
    public void testGetAndCheckCAEntity() {
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, entityName, "certificateAuthorityData.name")).thenReturn(caEntityData);
        assertEquals(caEntityData, cACertificatePersistenceHelper.getAndCheckCAEntity(entityName));
    }

    @Test
    public void testConfigCRLInfo() {

        final CAEntityData caEntityData = new CAEntityData();
        caEntityData.setExternalCA(true);
        final Set<CAEntityData> associated = new HashSet<CAEntityData>();
        final ExternalCRLInfoData externalCrlInfoData = new ExternalCRLInfoData();
        externalCrlInfoData.setUpdateUrl(updatedCRL);
        externalCrlInfoData.setAutoUpdate(true);
        externalCrlInfoData.setAutoUpdateCheckTimer(1);

        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setExternalCrlInfoData(externalCrlInfoData);
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        associated.add(caEntityData);
        caEntityData.setAssociated(associated);

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, entityName, "certificateAuthorityData.name")).thenReturn(caEntityData);
        cACertificatePersistenceHelper.configCRLInfo(entityName, true, 1000);

        Mockito.verify(persistenceManager, times(2)).updateEntity(caEntityData.getCertificateAuthorityData().getExternalCrlInfoData());
    }

    @Test
    public void testConfigCRLInfoWithOutAuto() {

        final CAEntityData caEntityData = new CAEntityData();
        final Set<CAEntityData> associated = new HashSet<CAEntityData>();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        final ExternalCRLInfoData externalCrlInfoData = new ExternalCRLInfoData();

        externalCrlInfoData.setUpdateUrl(updatedCRL);
        externalCrlInfoData.setAutoUpdate(false);
        certificateAuthorityData.setExternalCrlInfoData(externalCrlInfoData);

        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        caEntityData.setExternalCA(true);
        associated.add(caEntityData);
        caEntityData.setAssociated(associated);

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, entityName, "certificateAuthorityData.name")).thenReturn(caEntityData);
        cACertificatePersistenceHelper.configCRLInfo(entityName, true, 1000);

        Mockito.verify(persistenceManager, times(2)).updateEntity(caEntityData.getCertificateAuthorityData().getExternalCrlInfoData());
    }

    @Test
    public void testGetExternalCRLInfoForExtCA() {
        final List<ExternalCRLInfo> expected = new ArrayList<>();

        final Set<CAEntityData> associated = new HashSet<CAEntityData>();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setExternalCrlInfoData(externalCrlInfoData);
        final CAEntityData caEntityData2 = new CAEntityData();
        caEntityData2.setCertificateAuthorityData(certificateAuthorityData);
        associated.add(caEntityData2);

        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        caEntityData.setAssociated(associated);

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery("select ec from CAEntityData ec  WHERE ec.certificateAuthorityData.name = :name and ec.externalCA = true")).thenReturn(query);

        final List<CAEntityData> caEntityDatas = new ArrayList<CAEntityData>();
        caEntityDatas.add(caEntityData);
        Mockito.when(query.getResultList()).thenReturn(caEntityDatas);

        expected.add(externalCRLInfo);
        expected.add(externalCRLInfo);

        Mockito.when(crlMapper.toAPIFromModel(caEntityData.getCertificateAuthorityData().getExternalCrlInfoData())).thenReturn(externalCRLInfo);

        assertEquals(expected, cACertificatePersistenceHelper.getExternalCRLInfoForExtCA(entityName));
    }

    @Test(expected = ExternalCANotFoundException.class)
    public void testGetExternalCRLInfoForExtCAExternalCANotFoundException() {
        final List<ExternalCRLInfo> expected = new ArrayList<>();

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery("select ec from CAEntityData ec  WHERE ec.certificateAuthorityData.name = :name and ec.externalCA = true")).thenReturn(query);

        expected.add(externalCRLInfo);
        expected.add(externalCRLInfo);

        Mockito.when(crlMapper.toAPIFromModel(caEntityData.getCertificateAuthorityData().getExternalCrlInfoData())).thenReturn(externalCRLInfo);

        cACertificatePersistenceHelper.getExternalCRLInfoForExtCA(entityName);
    }

    @Test
    public void testGetTrustProfileNamesUsingExtCA() {
        final List<String> expected = new ArrayList<String>();
        final TrustProfileData trustProfileData = new TrustProfileData();
        final List<Object> trustProfileDatas = new ArrayList<>();
        trustProfileDatas.add(trustProfileData);
        final Map<String, Object> attributes = new HashMap<String, Object>();

        attributes.put("externalca_id", caEntityData.getId());
        attributes.put("is_active", true);

        expected.add(trustProfileData.getName());

        Mockito.when(persistenceManager.findEntitiesByAttributes(TRUST_PROFILE_QUERY, attributes)).thenReturn(trustProfileDatas);

        cACertificatePersistenceHelper.getTrustProfileNamesUsingExtCA(caEntityData);
        assertEquals(expected, cACertificatePersistenceHelper.getTrustProfileNamesUsingExtCA(caEntityData));
    }

    @Test
    public void testGetExpiredCRLs() {
        validation = new Date();
        final Map<String, Object> attributes = new HashMap<String, Object>();

        final SimpleDateFormat sdf = new SimpleDateFormat("yyyy-MM-dd");
        final String validityStr = sdf.format(validation);
        attributes.put("nextUpdateDate", validityStr);
        attributes.put("emptyString", "");

        final List<Object> externalCrlInfoDataList = new ArrayList<Object>();
        externalCrlInfoDataList.add(externalCrlInfoData);

        Mockito.when(
                persistenceManager
                        .findEntitiesByAttributes(
                                "select ecrl from ExternalCRLInfoData as ecrl where ecrl.autoUpdate = true and ecrl.nextUpdate < date(:nextUpdateDate) and ecrl.updateUrl is not null and  ecrl.updateUrl != :emptyString",
                                attributes)).thenReturn(externalCrlInfoDataList);

        assertEquals(externalCrlInfoDataList, cACertificatePersistenceHelper.getExpiredCRLs(validation));
    }

    @Test
    public void testGetLatestCertificateGenerationInfo() {
        qlString = QUERY_FOR_FETCH_LATEST_CSR;

        final List<CertificateGenerationInfoData> certificateGenerationInfoData = new ArrayList<CertificateGenerationInfoData>();
        certificateGenerationInfoData.add(certGenInfoData);
        Mockito.when(query.getResultList()).thenReturn(certificateGenerationInfoData);

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(qlString)).thenReturn(query);

        assertEquals(certificateGenerationInfoData.get(0), cACertificatePersistenceHelper.getLatestCertificateGenerationInfo(entityName));
    }

    @Test(expected = InvalidOperationException.class)
    public void testGetLatestCertificateGenerationInfoCertificateServiceException() {
        qlString = QUERY_FOR_FETCH_LATEST_CSR;

        final List<CertificateGenerationInfoData> certificateGenerationInfoData = new ArrayList<CertificateGenerationInfoData>();
        certificateGenerationInfoData.add(certGenInfoData);

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(qlString)).thenReturn(query);

        assertEquals(certificateGenerationInfoData.get(0), cACertificatePersistenceHelper.getLatestCertificateGenerationInfo(entityName));
    }

    @Test(expected = CertificateServiceException.class)
    public void testGetLatestCertificateGenerationInfoPersistException() {

        Mockito.doThrow(new PersistenceException()).when(persistenceManager).getEntityManager();

        cACertificatePersistenceHelper.getLatestCertificateGenerationInfo(entityName);
    }

    @Test
    public void testGetCSR() {
        qlString = QUERY_FOR_FETCH_LATEST_CSR;

        final List<CertificateGenerationInfoData> certificateGenerationInfoData = new ArrayList<CertificateGenerationInfoData>();
        certificateGenerationInfoData.add(certGenInfoData);
        Mockito.when(query.getResultList()).thenReturn(certificateGenerationInfoData);

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(qlString)).thenReturn(query);

        certificateRequestData = new CertificateRequestData();
        certificateRequestData.setCsr(certificateRequest);
        Mockito.when(certGenInfoData.getCertificateRequestData()).thenReturn(certificateRequestData);
        assertEquals(certificateRequestData.getCsr(), cACertificatePersistenceHelper.getCSR(entityName));
    }

    @Test
    public void testSetExpiredCRLs() {
        cACertificatePersistenceHelper.setExpiredCRLs(externalCrlInfoData);
        Mockito.verify(persistenceManager).updateEntity(externalCrlInfoData);
    }

    @Test
    public void testUpdateExtCA() {
        cACertificatePersistenceHelper.updateExtCA(caEntityData);
        Mockito.verify(persistenceManager).updateEntity(caEntityData);
    }

    @Test
    public void testDeleteExtCA() {
        cACertificatePersistenceHelper.deleteExtCA(caEntityData);
        Mockito.verify(persistenceManager).deleteEntity(caEntityData);
    }

    @Test
    public void testDeleteExternalCRLInfo() {
        cACertificatePersistenceHelper.deleteExternalCRLInfo(externalCrlInfoData);
        Mockito.verify(persistenceManager).deleteEntity(externalCrlInfoData);
    }

    @Test
    public void testGetCertificatesCount() {
        qlString = "select c from CertificateData c where c.id in(select p.id from CAEntityData ec inner join ec.certificateAuthorityData.certificateDatas p  WHERE ec.certificateAuthorityData.name = :name and p.serialNumber= :serialnumber)";
        final int count = 0;
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(qlString)).thenReturn(query);
        assertEquals(count, cACertificatePersistenceHelper.getCertificatesCount(entityName, certificate.getSerialNumber()));
    }

    @Test
    public void testUpdateIsIssuerExternalCAFlag() {

        cACertificatePersistenceHelper.updateIsIssuerExternalCAFlag(caEntityData, true);
        Mockito.verify(persistenceManager).updateEntity(caEntityData);
    }

    @Test(expected = CertificateServiceException.class)
    public void testUpdateIsIssuerExternalCAFlagCertificateServiceException() {

        Mockito.doThrow(new PersistenceException()).when(persistenceManager).updateEntity(caEntityData);
        cACertificatePersistenceHelper.updateIsIssuerExternalCAFlag(caEntityData, true);
    }

    @Test
    public void testCheckAndUpdateIsIssuerExternalCA() {

        final CAEntityData caEntityData = new CAEntityData();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();

        certificateAuthorityData.setRootCA(true);
        certificateAuthorityData.setIssuerExternalCA(true);
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, entityName, Constants.CA_NAME_PATH)).thenReturn(caEntityData);
        cACertificatePersistenceHelper.checkAndUpdateIsIssuerExternalCA(entityName);

        Mockito.verify(persistenceManager).updateEntity(caEntityData);
    }

    @Test(expected = CertificateServiceException.class)
    public void testCheckAndUpdateIsIssuerExternalCAPersisteException() {

        final CAEntityData caEntityData = new CAEntityData();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();

        certificateAuthorityData.setRootCA(true);
        certificateAuthorityData.setIssuerExternalCA(true);
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, entityName, Constants.CA_NAME_PATH)).thenReturn(caEntityData);
        Mockito.doThrow(new PersistenceException()).when(persistenceManager).updateEntity(caEntityData);
        cACertificatePersistenceHelper.checkAndUpdateIsIssuerExternalCA(entityName);
    }

    @Test
    public void testUpdateIssuerCAandCertificate() {
        cACertificatePersistenceHelper.updateIssuerCAandCertificate(certificateData, caEntityData, issuerCertificateData);
        Mockito.verify(persistenceManager).updateEntity(certificateData);
    }

    @Test(expected = CertificateServiceException.class)
    public void testUpdateIssuerCAandCertificatePersistException() {

        Mockito.doThrow(new PersistenceException()).when(persistenceManager).updateEntity(certificateData);
        cACertificatePersistenceHelper.updateIssuerCAandCertificate(certificateData, caEntityData, issuerCertificateData);
    }

    @Test
    public void testGetExpiredCACertificatesToUnpublish() {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);

        Mockito.when(entityManager.createQuery(CA_NAMES_BY_STATUS)).thenReturn(query);
        Mockito.when(cACertificatePersistenceHelper.getAllCANameByStatus(CAStatus.ACTIVE, CAStatus.INACTIVE)).thenReturn(Arrays.asList("CANAME1"));

        Query query1 = Mockito.mock(Query.class);
        Mockito.when(entityManager.createQuery(CAENTITY_CERTIFICATES_BY_CANAME_AND_STATUS)).thenReturn(query1);

        CertificateData certificateData = new CertificateData();
        certificateData.setPublishedToTDPS(true);
        Mockito.when(query1.getResultList()).thenReturn(Arrays.asList(certificateData));
        try {
            Mockito.when(certificateModelMapper.toObjectModel(Arrays.asList(certificateData))).thenReturn(Arrays.asList(certificate));
        } catch (CertificateException | IOException e) {
            Assert.fail(e.getMessage());
        }

        final Map<String, List<Certificate>> entityCertsMap = cACertificatePersistenceHelper.getExpiredCACertificatesToUnpublish();
        assertFalse(entityCertsMap.isEmpty());
    }

    @Test
    public void testGetAllCANameByStatus() {
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);

        Mockito.when(entityManager.createQuery(CA_NAMES_BY_STATUS)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(Arrays.asList("CANAME1"));

        final List<String> caNames = cACertificatePersistenceHelper.getAllCANameByStatus(CAStatus.ACTIVE, CAStatus.INACTIVE);
        assertNotNull(caNames);
        assertFalse(caNames.isEmpty());
    }
}
