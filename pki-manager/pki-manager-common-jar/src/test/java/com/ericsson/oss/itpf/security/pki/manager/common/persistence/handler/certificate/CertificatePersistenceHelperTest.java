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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate;

import static org.junit.Assert.*;
import static org.mockito.Mockito.times;

import java.io.IOException;
import java.math.BigInteger;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.*;

import javax.persistence.*;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data.SetUPData;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.certificate.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.certificate.CertificateModelMapperV1;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.result.mapper.CertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.FilterResponseType;
import com.ericsson.oss.itpf.security.pki.manager.exception.revocation.IssuerNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateChain;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.CertificateInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.DNBasedCertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.manager.model.certificates.filter.CertificateFilter;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

@RunWith(MockitoJUnitRunner.class)
public class CertificatePersistenceHelperTest {

    @InjectMocks
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Mock
    Logger logger;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    CertificateModelMapper certificateModelMapper;

    @Mock
    CertificateModelMapperV1 certificateModelMapper_v1;

    @Mock
    CertificateFilterDynamicQueryBuilder certificateFilterDynamicQueryBuilder;

    @Mock
    EntityManager entityManager;

    @Mock
    Query query;

    @Mock
    DNBasedCertificateIdentifier dnBasedCertificateIdentifier;

    private CertificateData certificateData;
    private CertificateIdentifier certificateIdentifier;
    private List<CertificateData> certDataList;
    private List<CertificateData> certDatas;
    private Certificate certificate;
    private CAEntityData caEntityData;
    private List<Certificate> certificates;
    private Map<String, Object> certificateMap;
    private static CertificateAuthority certificateAuthority;
    private X509Certificate x509Certificate;
    private CACertificateIdentifier caCertificateIdentifier;

    private static SetUPData setUPData = new SetUPData();

    private final static CertificateStatus certificatestatus = CertificateStatus.ACTIVE;

    @Before
    public void setUp() throws CertificateException, IOException {

        caEntityData = new CAEntityData();
        caEntityData.setId(10111);
        caEntityData.setExternalCA(true);

        certificateAuthority = new CertificateAuthority();
        certificateAuthority.setId(10111);
        certificateAuthority.setName("subCA");

        certificate = new Certificate();
        certificate.setId(101);
        certificate.setIssuedTime(new Date());
        certificate.setSerialNumber("10101");
        certificate.setStatus(CertificateStatus.ACTIVE);
        certificate.setIssuer(certificateAuthority);
        certificate.setX509Certificate(x509Certificate);
        certificates = new LinkedList<Certificate>();

        certificates.add(certificate);

        certificateIdentifier = new CertificateIdentifier();
        certificateIdentifier.setIssuerName("Ericssion");
        certificateIdentifier.setSerialNumber("324567");

        certificateData = new CertificateData();
        certificateData.setId(101);
        certificateData.setSerialNumber("10101");
        certificateData.setIssuedTime(new Date());

        certDataList = new LinkedList<CertificateData>();
        certDataList.add(certificateData);

        certDatas = new ArrayList<CertificateData>();
        certDatas.add(certificateData);

        certificateMap = new HashMap<String, Object>();
        certificateMap.put("serialNumber", certificateIdentifier.getSerialNumber());

        x509Certificate = setUPData.getX509Certificate("certificates/ENMRootCA.crt");

        caCertificateIdentifier = new CACertificateIdentifier();
    }

    @Test
    public void testGetCertificate() {

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, certificateIdentifier.getIssuerName(), Constants.CA_NAME_PATH)).thenReturn(caEntityData);

        try {
            Mockito.when(certificateModelMapper.toObjectModel(certDataList)).thenReturn(certificates);
        } catch (IOException | CertificateException e) {

        }

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateData.class, certificateMap)).thenReturn(certDataList);

        final Certificate certificate = certificatePersistenceHelper.getCertificate(certificateIdentifier);
        assertNotNull(certificate);
    }

    @Test(expected = CertificateServiceException.class)
    public void testGetCertificate_CertificateServiceException() {

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, certificateIdentifier.getIssuerName(), Constants.CA_NAME_PATH)).thenReturn(caEntityData);

        try {
            Mockito.when(certificateModelMapper.toObjectModel(certDataList)).thenReturn(certificates);
        } catch (IOException | CertificateException e) {

        }

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateData.class, certificateMap)).thenThrow(new PersistenceException());

        certificatePersistenceHelper.getCertificate(certificateIdentifier);

    }

    @Test(expected = CertificateNotFoundException.class)
    public void testGetCertificate_CertificateNotFoundException() {

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, certificateIdentifier.getIssuerName(), Constants.CA_NAME_PATH)).thenReturn(caEntityData);

        try {
            Mockito.when(certificateModelMapper.toObjectModel(certDataList)).thenReturn(certificates);
        } catch (IOException | CertificateException e) {

        }

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateData.class, certificateMap)).thenReturn(null);

        certificatePersistenceHelper.getCertificate(certificateIdentifier);

        Mockito.verify(persistenceManager, times(1)).findEntityByName(CAEntityData.class, certificateIdentifier.getIssuerName(), Constants.CA_NAME_PATH);
        try {
            Mockito.verify(certificateModelMapper, times(1)).toObjectModel(certDataList);
        } catch (CertificateException | IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        Mockito.verify(persistenceManager, times(1)).findEntitiesByAttributes(CertificateData.class, certificateMap);

    }

    @Test(expected = CertificateServiceException.class)
    public void testGetCertificate_CertificateServiceException_2() {

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, certificateIdentifier.getIssuerName(), Constants.CA_NAME_PATH)).thenReturn(caEntityData);

        try {
            Mockito.when(certificateModelMapper.toObjectModel(certDataList)).thenThrow(new IOException());
        } catch (IOException | CertificateException e) {

        }

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateData.class, certificateMap)).thenReturn(certDataList);

        certificatePersistenceHelper.getCertificate(certificateIdentifier);

    }

    @Test(expected = CertificateServiceException.class)
    public void testGetCertificate_CertificateServiceException_3() {

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, certificateIdentifier.getIssuerName(), Constants.CA_NAME_PATH)).thenReturn(caEntityData);

        try {
            Mockito.when(certificateModelMapper.toObjectModel(certDataList)).thenThrow(new CertificateException());
        } catch (IOException | CertificateException e) {

        }

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateData.class, certificateMap)).thenReturn(certDataList);

        certificatePersistenceHelper.getCertificate(certificateIdentifier);

    }

    @Test(expected = CertificateServiceException.class)
    public void testGetCertificate_CertificateServiceException_4() {

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, certificateIdentifier.getIssuerName(), Constants.CA_NAME_PATH)).thenThrow(new PersistenceException());
        try {
            Mockito.when(certificateModelMapper.toObjectModel(certDataList)).thenReturn(certificates);
        } catch (IOException | CertificateException e) {

        }

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateData.class, certificateMap)).thenReturn(certDataList);

        certificatePersistenceHelper.getCertificate(certificateIdentifier);

        Mockito.verify(persistenceManager, times(1)).findEntityByName(CAEntityData.class, certificateIdentifier.getIssuerName(), Constants.CA_NAME_PATH);

        try {
            Mockito.verify(certificateModelMapper, times(1)).toObjectModel(certDataList);
        } catch (CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        Mockito.verify(persistenceManager, times(1)).findEntitiesByAttributes(CertificateData.class, certificateMap);

    }

    @Test(expected = IssuerNotFoundException.class)
    public void testGetCertificate_IssuerNotFoundException() {

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, certificateIdentifier.getIssuerName(), Constants.CA_NAME_PATH)).thenReturn(null);

        try {
            Mockito.when(certificateModelMapper.toObjectModel(certDataList)).thenReturn(certificates);
        } catch (IOException | CertificateException e) {

        }

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateData.class, certificateMap)).thenReturn(certDataList);

        certificatePersistenceHelper.getCertificate(certificateIdentifier);

        Mockito.verify(persistenceManager, times(1)).findEntityByName(CAEntityData.class, certificateIdentifier.getIssuerName(), Constants.CA_NAME_PATH);

        try {
            Mockito.verify(certificateModelMapper, times(1)).toObjectModel(certDataList);
        } catch (CertificateException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        } catch (IOException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
        }
        Mockito.verify(persistenceManager, times(1)).findEntitiesByAttributes(CertificateData.class, certificateMap);

    }

    @Test
    public void testGetCertificateData() {

        certificateMap.clear();
        certificateMap.put("id", certificate.getId());

        Mockito.when(persistenceManager.findEntitiesWhere(CertificateData.class, certificateMap)).thenReturn(certDataList);

        certificatePersistenceHelper.getCertificateData(certificate);

        Mockito.verify(persistenceManager, times(1)).findEntitiesWhere(CertificateData.class, certificateMap);

    }

    @Test(expected = CertificateServiceException.class)
    public void testGetCertificateData_CertificateServiceException() {

        final Map<String, Object> certificateMap = new HashMap<String, Object>();
        certificateMap.put("id", certificate.getId());

        Mockito.when(persistenceManager.findEntitiesWhere(CertificateData.class, certificateMap)).thenThrow(new PersistenceException());

        certificatePersistenceHelper.getCertificateData(certificate);

        Mockito.verify(persistenceManager, times(1)).findEntitiesWhere(CertificateData.class, certificateMap);

    }

    @Test
    public void testGetCertificates() {

        final FilterResponseType responseType = FilterResponseType.LIST;
        final EnumSet<EntityType> entityTypeFilter = EnumSet.of(EntityType.CA_ENTITY);
        final CertificateFilter certificateFilter = new CertificateFilter();
        CertificateStatus[] certificateStatusList = new CertificateStatus[1];
        for (int i = 0; i < 1; i++) {
            certificateStatusList[i] = certificatestatus;
        }
        certificateFilter.setCertificateStatusList(certificateStatusList);
        certificateFilter.setIssuerDN("MyRoot");
        certificateFilter.setOffset(0);
        certificateFilter.setLimit(1);
        StringBuilder dynamicQuery = new StringBuilder();
        StringBuilder query = new StringBuilder();

        dynamicQuery.append("SELECT c.* from certificate c  LEFT JOIN ca_certificate cc on c.id = cc.certificate_id   LEFT JOIN caentity ca on ca.id = cc.ca_id ");

        query.append("SELECT c.* from certificate c  LEFT JOIN ca_certificate cc on c.id = cc.certificate_id   LEFT JOIN caentity ca on ca.id = cc.ca_id ");

        Mockito.when(certificateFilterDynamicQueryBuilder.buildCertificatesQuery(certificateFilter, entityTypeFilter, responseType, new HashMap<String, Object>())).thenReturn(dynamicQuery);
        Mockito.when(certificateFilterDynamicQueryBuilder.replaceQueryString(entityTypeFilter, dynamicQuery, responseType)).thenReturn(query);
        Mockito.when(persistenceManager.findEntitiesByNativeQuery(CertificateData.class, query.toString(), new HashMap<String, Object>(), certificateFilter.getOffset(), certificateFilter.getLimit()))
                .thenReturn(certDatas);

        final List<CertificateData> certificates = (List<CertificateData>) certificatePersistenceHelper.getCertificates(certificateFilter, entityTypeFilter, responseType);

        assertNotNull(certificates);
        assertTrue(!certificates.isEmpty());
        assertEquals(certificates.get(0).getId(), certDatas.get(0).getId());
        assertEquals(certificates.get(0).getSerialNumber(), certDatas.get(0).getSerialNumber());
    }

    @Test
    public void testGetCertificates_Count() {
        final FilterResponseType responseType = FilterResponseType.COUNT;
        final EnumSet<EntityType> entityTypeFilter = EnumSet.of(EntityType.CA_ENTITY);
        final CertificateFilter certificateFilter = new CertificateFilter();
        CertificateStatus[] certificateStatusList = new CertificateStatus[1];
        for (int i = 0; i < 1; i++) {
            certificateStatusList[i] = certificatestatus;
        }
        certificateFilter.setCertificateStatusList(certificateStatusList);
        certificateFilter.setIssuerDN("MyRoot");
        StringBuilder dynamicQuery = new StringBuilder();
        StringBuilder query = new StringBuilder();

        dynamicQuery.append("SELECT c.* from certificate c  LEFT JOIN ca_certificate cc on c.id = cc.certificate_id   LEFT JOIN caentity ca on ca.id = cc.ca_id ");

        query.append("SELECT COUNT(*) from certificate c  LEFT JOIN ca_certificate cc on c.id = cc.certificate_id   LEFT JOIN caentity ca on ca.id = cc.ca_id ");

        Mockito.when(certificateFilterDynamicQueryBuilder.buildCertificatesQuery(certificateFilter, entityTypeFilter, responseType, new HashMap<String, Object>())).thenReturn(dynamicQuery);
        Mockito.when(certificateFilterDynamicQueryBuilder.replaceQueryString(entityTypeFilter, dynamicQuery, responseType)).thenReturn(query);
        Mockito.when(persistenceManager.findEntityCountByNativeQuery(query.toString(), new HashMap<String, Object>())).thenReturn(1);

        final Integer count = (Integer) certificatePersistenceHelper.getCertificates(certificateFilter, entityTypeFilter, responseType);
        assertNotNull(count);
        assertNotNull(count > 0);
    }

    @Test
    public void testGetCertificates_Entity() {

        final FilterResponseType responseType = FilterResponseType.COUNT;
        final EnumSet<EntityType> entityTypeFilter = EnumSet.of(EntityType.ENTITY);
        final CertificateFilter certificateFilter = new CertificateFilter();
        CertificateStatus[] certificateStatusList = new CertificateStatus[1];
        for (int i = 0; i < 1; i++) {
            certificateStatusList[i] = certificatestatus;
        }
        certificateFilter.setCertificateStatusList(certificateStatusList);
        certificateFilter.setIssuerDN("MyRoot");
        StringBuilder dynamicQuery = new StringBuilder();
        StringBuilder query = new StringBuilder();

        dynamicQuery.append("SELECT c.* from certificate c  LEFT JOIN ca_certificate cc on c.id = cc.certificate_id   LEFT JOIN caentity ca on ca.id = cc.ca_id ");

        query.append("SELECT COUNT(*) from certificate c  LEFT JOIN ca_certificate cc on c.id = cc.certificate_id   LEFT JOIN caentity ca on ca.id = cc.ca_id ");

        Mockito.when(certificateFilterDynamicQueryBuilder.buildCertificatesQuery(certificateFilter, entityTypeFilter, responseType, new HashMap<String, Object>())).thenReturn(dynamicQuery);
        Mockito.when(certificateFilterDynamicQueryBuilder.replaceQueryString(entityTypeFilter, dynamicQuery, responseType)).thenReturn(query);
        Mockito.when(persistenceManager.findEntityCountByNativeQuery(query.toString(), new HashMap<String, Object>())).thenReturn(1);

        final Integer count = (Integer) certificatePersistenceHelper.getCertificates(certificateFilter, entityTypeFilter, responseType);
        assertNotNull(count);
        assertNotNull(count > 0);
    }

    @Test
    public void testGetCertificateChain_Entity() throws CertificateException, IOException {

        final Certificate entityCertificate = setUPData.getEntityCertificate();
        entityCertificate.setId(101);

        certificateMap.clear();
        certificateMap.put("id", entityCertificate.getId());
        final List<CertificateData> certificateDatas = setUPData.getCertificateDatas(EntityType.ENTITY);
        Mockito.when(persistenceManager.findEntitiesWhere(CertificateData.class, certificateMap)).thenReturn(certificateDatas);

        final CertificateChain activeCertChain = setUPData.getEntityCertificateChain(CertificateStatus.ACTIVE);
        final List<Certificate> activeCertificates = activeCertChain.getCertificates();
        Mockito.when(certificateModelMapper_v1.toApi(certificateDatas, MappingDepth.LEVEL_1)).thenReturn(activeCertificates);

        final List<Certificate> certificates = certificatePersistenceHelper.getCertificateChain(entityCertificate, Constants.INACTIVE_CERTIFICATE_VALID);

        assertNotNull(certificates);
        assertEquals(activeCertificates, certificates);

    }

    @Test
    public void testGetCertificateChain_Entity_Issuer_Certificate_Revoked() throws CertificateException, IOException {

        final Certificate entityCertificate = setUPData.getEntityCertificate();
        entityCertificate.setId(101);

        certificateMap.clear();
        certificateMap.put("id", entityCertificate.getId());
        final List<CertificateData> certificateDatas = setUPData.getCertificateDatas(EntityType.ENTITY);
        certificateDatas.get(0).getIssuerCertificate().setStatus(3);
        Mockito.when(persistenceManager.findEntitiesWhere(CertificateData.class, certificateMap)).thenReturn(certificateDatas);

        assertNull(certificatePersistenceHelper.getCertificateChain(entityCertificate, Constants.INACTIVE_CERTIFICATE_VALID));
    }

    @Test(expected = CertificateServiceException.class)
    public void testGetCertificateChain_UNEXPECTED_ERROR() throws CertificateException, IOException {

        final Certificate entityCertificate = setUPData.getEntityCertificate();
        entityCertificate.setId(101);

        certificateMap.clear();
        certificateMap.put("id", entityCertificate.getId());
        final List<CertificateData> certificateDatas = setUPData.getCertificateDatas(EntityType.ENTITY);
        Mockito.when(persistenceManager.findEntitiesWhere(CertificateData.class, certificateMap)).thenReturn(certificateDatas);

        Mockito.when(certificateModelMapper_v1.toApi(certificateDatas, MappingDepth.LEVEL_1)).thenThrow(new CertificateException());

        certificatePersistenceHelper.getCertificateChain(entityCertificate, Constants.INACTIVE_CERTIFICATE_VALID);
    }

    @Test
    public void testGetCertificateChain_CAEntity() throws CertificateException, IOException {

        final Certificate entityCertificate = setUPData.getCAEntityCertificate();
        entityCertificate.setId(111);

        certificateMap.clear();
        certificateMap.put("id", entityCertificate.getId());
        final List<CertificateData> certificateDatas = setUPData.getCertificateDatas(EntityType.CA_ENTITY);
        Mockito.when(persistenceManager.findEntitiesWhere(CertificateData.class, certificateMap)).thenReturn(certificateDatas);

        CertificateChain activeCertChain = setUPData.getCAEntityCertificateChain(CertificateStatus.ACTIVE);
        final List<Certificate> activeCertificates = activeCertChain.getCertificates();
        Mockito.when(certificateModelMapper_v1.toApi(certificateDatas, MappingDepth.LEVEL_1)).thenReturn(activeCertificates);

        final List<Certificate> certificates = certificatePersistenceHelper.getCertificateChain(entityCertificate, Constants.INACTIVE_CERTIFICATE_VALID);

        assertNotNull(certificates);
        assertEquals(activeCertificates, certificates);

    }

    @Test
    public void testValidateCertificateChain() {
        final CertificateData certData = new CertificateData();
        final CertificateData issuerCertData = new CertificateData();
        issuerCertData.setSubjectDN("ENM_RootCA");
        issuerCertData.setStatus(1);
        certData.setSubjectDN("ENM_SubCA");
        certData.setStatus(1);
        certData.setIssuerCertificate(issuerCertData);
        certificatePersistenceHelper.validateCertificateChain(certData, EnumSet.of(CertificateStatus.REVOKED));
    }

    @Test(expected = RevokedCertificateException.class)
    public void testValidateCertificateChain_Exception() {
        final CertificateData certData = new CertificateData();
        final CertificateData issuerCertData = new CertificateData();
        issuerCertData.setSubjectDN("ENM_RootCA");
        issuerCertData.setStatus(3);
        certData.setSubjectDN("ENM_SubCA");
        certData.setStatus(1);
        certData.setIssuerCertificate(issuerCertData);
        certificatePersistenceHelper.validateCertificateChain(certData, EnumSet.of(CertificateStatus.REVOKED));
    }

    @Test
    public void testValidateCertificateChainWithCertIdentifier() {
        final CertificateData certData = new CertificateData();
        final CertificateData issuerCertData = new CertificateData();
        issuerCertData.setSubjectDN("ENM_RootCA");
        issuerCertData.setStatus(1);
        certData.setSubjectDN("ENM_SubCA");
        certData.setStatus(1);
        certData.setIssuerCertificate(issuerCertData);

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);
        Mockito.when(query.getSingleResult()).thenReturn(certData);
        certificatePersistenceHelper.validateCertificateChain(caCertificateIdentifier, EnumSet.of(CertificateStatus.REVOKED));
    }

    /**
     * Method to test for empty certificate expiry notification details
     */
    @Test
    public void testGetCertExpiryNotificationDetails_CA_Empty() {
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createNativeQuery(Mockito.anyString())).thenReturn(query);
        final List<Object[]> certExpiryNotificationDetailsList = new ArrayList<Object[]>();
        Mockito.when(query.getResultList()).thenReturn(certExpiryNotificationDetailsList);
        final List<CertificateExpiryNotificationDetails> actualCertExpiryNotificationDetailsList = certificatePersistenceHelper.getCertExpiryNotificationDetails(EntityType.CA_ENTITY);
        Assert.assertTrue(actualCertExpiryNotificationDetailsList.isEmpty());
    }

    /**
     * Method to test for empty certificate expiry notification details
     */
    @Test
    public void testGetCertExpiryNotificationDetails_Entity_Empty() {
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createNativeQuery(Mockito.anyString())).thenReturn(query);
        final List<Object[]> certExpiryNotificationDetailsList = new ArrayList<Object[]>();
        Mockito.when(query.getResultList()).thenReturn(certExpiryNotificationDetailsList);
        final List<CertificateExpiryNotificationDetails> actualCertExpiryNotificationDetailsList = certificatePersistenceHelper.getCertExpiryNotificationDetails(EntityType.ENTITY);
        Assert.assertTrue(actualCertExpiryNotificationDetailsList.isEmpty());
    }

    /**
     * Method to test CA certificate expiry notification details
     */
    @Test
    public void testGetCertExpiryNotificationDetails_CA() {

        final String caName = "CAENTITY";
        final String subjectDn = "CN=ARJ_ROOTCA";
        final String serialNumber = "4af7cb2ef4ea";
        final String notificationMessage = "Certificate for CA Entity: CAEntity With SubjectDN CN=ARJ_ROOT_CA and Serial Number 4af7cb2ef4ea will expire in 25 DAYS.Refer Security System Administration Guide for  Certificate Reissue procedure.";

        Object[] certExpiryNotificationDetails = new Object[8];

        certExpiryNotificationDetails[0] = caName;
        certExpiryNotificationDetails[1] = subjectDn;
        certExpiryNotificationDetails[2] = serialNumber;
        certExpiryNotificationDetails[3] = new Integer(25);
        certExpiryNotificationDetails[4] = new Integer(30);
        certExpiryNotificationDetails[6] = new Integer(1);
        certExpiryNotificationDetails[5] = new Integer(1);
        certExpiryNotificationDetails[7] = notificationMessage;

        final List<Object[]> certExpiryNotificationDetailsList = new ArrayList<Object[]>();
        certExpiryNotificationDetailsList.add(certExpiryNotificationDetails);

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createNativeQuery(Mockito.anyString())).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(certExpiryNotificationDetailsList);
        final List<CertificateExpiryNotificationDetails> actualCertExpiryNotificationDetailsList = certificatePersistenceHelper.getCertExpiryNotificationDetails(EntityType.CA_ENTITY);

        final CertificateExpiryNotificationDetails actualCertExpNotificationDetailsDTO = actualCertExpiryNotificationDetailsList.get(0);

        Assert.assertEquals(caName, actualCertExpNotificationDetailsDTO.getName());
        Assert.assertEquals(subjectDn, actualCertExpNotificationDetailsDTO.getSubjectDN());
        Assert.assertEquals(serialNumber, actualCertExpNotificationDetailsDTO.getSerialNumber());
        Assert.assertEquals(notificationMessage, actualCertExpNotificationDetailsDTO.getNotificationMessage());

    }

    /**
     * Method to test Entity certificate expiry notification details
     */
    @Test
    public void testGetCertExpiryNotificationDetails_Entity() {
        Object[] certExpiryNotificationDetails = new Object[8];

        final String entityName = "ENTITY";
        final String subjectDn = "CN=ARJ_ROOTCA";
        final String serialNumber = "4af7cb2ef4ea";
        final String notificationMessage = "Certificate for CA Entity: CAEntity With SubjectDN CN=ARJ_ROOT_CA and Serial Number 4af7cb2ef4ea will expire in 25 DAYS.Refer Security System Administration Guide for  Certificate Reissue procedure.";

        certExpiryNotificationDetails[0] = entityName;
        certExpiryNotificationDetails[1] = subjectDn;
        certExpiryNotificationDetails[2] = serialNumber;
        certExpiryNotificationDetails[3] = new Integer(55);
        certExpiryNotificationDetails[4] = new Integer(60);
        certExpiryNotificationDetails[6] = new Integer(1);
        certExpiryNotificationDetails[5] = new Integer(1);
        certExpiryNotificationDetails[7] = notificationMessage;

        final List<Object[]> certExpiryNotificationDetailsList = new ArrayList<Object[]>();
        certExpiryNotificationDetailsList.add(certExpiryNotificationDetails);
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createNativeQuery(Mockito.anyString())).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(certExpiryNotificationDetailsList);
        final List<CertificateExpiryNotificationDetails> actualCertExpiryNotificationDetailsList = certificatePersistenceHelper.getCertExpiryNotificationDetails(EntityType.ENTITY);

        final CertificateExpiryNotificationDetails actualCertExpNotificationDetails = actualCertExpiryNotificationDetailsList.get(0);

        Assert.assertEquals(entityName, actualCertExpNotificationDetails.getName());
        Assert.assertEquals(subjectDn, actualCertExpNotificationDetails.getSubjectDN());
        Assert.assertEquals(serialNumber, actualCertExpNotificationDetails.getSerialNumber());
        Assert.assertEquals(notificationMessage, actualCertExpNotificationDetails.getNotificationMessage());
    }

    /**
     * Method to test Persistence Exception
     */
    @Test
    public void testGetCertExpNotificationDetails_PersistenceException() throws PersistenceException {
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createNativeQuery(Mockito.anyString())).thenReturn(query).thenThrow(new PersistenceException("error occured while fetching the data"));
        certificatePersistenceHelper.getCertExpiryNotificationDetails(EntityType.CA_ENTITY);
    }

    @Test
    public void testUpdateCertificateStatusToExpired() {
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery("UPDATE  CertificateData c SET  c.status=(:status) WHERE c.notAfter <= (:currDate) AND c.status IN (:certStatus)")).thenReturn(query);
        certificatePersistenceHelper.updateCertificateStatusToExpired();

        Mockito.verify(query).executeUpdate();
    }

    @Test
    public void testGetCertificatesInfoByIssuerCA() {
        final Long[] issuerCertificateIds = { (long) 0 };
        final BigInteger big[] = new BigInteger[1];
        big[0] = new BigInteger("2");

        final StringBuilder certsIssuedByCA = new StringBuilder();

        final CertificateStatus[] status = { certificatestatus };

        final List<Object[]> results = new ArrayList<Object[]>();
        final CertificateInfo cInfo = new CertificateInfo();
        Object[] objectList = new Object[9];
        objectList[0] = big[0];
        objectList[1] = cInfo.getEntityName();
        objectList[2] = true;
        objectList[3] = cInfo.getSubject();
        objectList[4] = cInfo.getSubjectAltName();
        objectList[5] = cInfo.getSerialNumber();
        objectList[6] = cInfo.getNotAfter();
        objectList[7] = cInfo.getNotBefore();
        objectList[6] = cInfo.getStatus();

        results.add(objectList);

        certsIssuedByCA
                .append("SELECT c.id,CASE WHEN ca.name is null THEN e.name ELSE ca.name END,CASE WHEN ca.name is null THEN false ELSE true END,c.subject_dn,c.subject_alt_name,c.serial_number,c.not_after,c.not_before,c.status_id from certificate c");
        certsIssuedByCA.append(" LEFT JOIN ca_certificate cc on c.id = cc.certificate_id  LEFT JOIN caentity ca on ca.id = cc.ca_id  ");
        certsIssuedByCA.append(" LEFT JOIN entity_certificate ec on c.id = ec.certificate_id LEFT JOIN entity e on e.id = ec.entity_id ");
        certsIssuedByCA.append(" WHERE c.issuer_certificate_id IN " + certificateFilterDynamicQueryBuilder.inOperatorValues(issuerCertificateIds));
        certsIssuedByCA.append(" and c.status_id IN " + certificateFilterDynamicQueryBuilder.inOperatorValues(certificateFilterDynamicQueryBuilder.getCertificateStatusArray(status)));
        certsIssuedByCA.append(certificateFilterDynamicQueryBuilder.orderBy("c.issued_time", "DESC"));

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createNativeQuery(certsIssuedByCA.toString())).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(results);

        List<CertificateInfo> certificateInfos = certificatePersistenceHelper.getCertificatesInfoByIssuerCA(issuerCertificateIds, certificatestatus);
        System.out.println("certificateInfos :" + certificateInfos);
        assertNotNull(certificateInfos);
    }

    @Test
    public void testGetCertificateIds() {
        final StringBuilder dynamicQuery = new StringBuilder();

        dynamicQuery.append("SELECT id from  CertificateData cert ");

        final Map<String, Object> parameters = certificateFilterDynamicQueryBuilder.where(dnBasedCertificateIdentifier, dynamicQuery);

        final Certificate cert = new Certificate();
        cert.setId(1010101);

        final List<Object> results = new ArrayList<Object>();

        results.add(cert.getId());

        Mockito.when(persistenceManager.findEntitiesByAttributes(dynamicQuery.toString(), parameters)).thenReturn(results);
        certificatePersistenceHelper.getCertificates(dnBasedCertificateIdentifier);
        Mockito.verify(persistenceManager).findEntitiesByAttributes(dynamicQuery.toString(), parameters);
    }

    @Test
    public void testGetCertificatesFromX509Certificate() throws CertificateException, IOException {

        final String serialNumber = Long.toHexString(x509Certificate.getSerialNumber().longValue());

        final Map<String, Object> certificateMap = new HashMap<String, Object>();
        certificateMap.put("serialNumber", serialNumber);

        final List<Certificate> certificates;
        final Certificate certificate = new Certificate();
        certificate.setId(101);
        certificate.setIssuedTime(new Date());
        certificate.setSerialNumber("10101");
        certificate.setStatus(CertificateStatus.ACTIVE);
        certificate.setIssuer(certificateAuthority);
        certificate.setX509Certificate(x509Certificate);
        certificates = new LinkedList<Certificate>();

        certificates.add(certificate);

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateData.class, certificateMap)).thenReturn(certDataList);

        Mockito.when(certificateModelMapper.toObjectModel(certDataList)).thenReturn(certificates);

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateData.class, certificateMap)).thenReturn(certDataList);

        assertEquals(certificate, certificatePersistenceHelper.getCertificate(x509Certificate));
    }

    @Test
    public void testGetCertificateWithCertID() {
        String qlString = "select c from CertificateData c where c.id in(select cd.id from CAEntityData caData inner join caData.certificateAuthorityData.certificateDatas cd  WHERE caData.certificateAuthorityData.name = :name and cd.serialNumber = :serialNumber)";
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(qlString)).thenReturn(query);
        Mockito.when(query.getSingleResult()).thenReturn(certificateData);
        assertEquals(certificateData, certificatePersistenceHelper.getCertificate(caCertificateIdentifier));
    }
}
