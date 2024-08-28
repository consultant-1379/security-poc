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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.crl;

/**
 * Test class for CRLPersistenceHandler.
 */
import static org.junit.Assert.*;

import java.io.IOException;
import java.util.*;

import javax.persistence.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.*;
import com.ericsson.oss.itpf.security.pki.manager.common.data.CRLSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.OperationType;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.crl.CRLInfoMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.CAEntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;

@RunWith(MockitoJUnitRunner.class)
public class CRLPersistenceHandlerTest {
    private static final String CRL_STATUS = "status";

    @InjectMocks
    CRLPersistenceHandler cRLPersistenceHandler;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    CAEntityPersistenceHandler caEntityPersistenceHandler;

    @Mock
    Logger logger;

    @Mock
    CAEntityMapper caEntityMapper;

    @Mock
    EntityManager entityManager;

    @Mock
    CRLInfoMapper crlInfoMapper;

    @Mock
    Query query;

    @Mock
    SystemRecorder systemRecorder;

    private static CAEntity caEntity;
    private static CAEntityData caEntityData;
    private static CertificateAuthority certificateAuthority;
    private static CertificateAuthorityData certAuthorityData;
    private static CRLInfo cRlInfo;
    private static CAEntityData cAEntityData;
    private static CAEntityData cAEntityDataForGetLatestCRL;
    private static CRLInfoData crlInfoData;
    private static Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
    private static Set<CRLInfoData> crlInfoDatas = new HashSet<CRLInfoData>();
    private static CertificateData certificateData;

    /**
     * Prepares initial Data.
     */

    @Before
    public void setUpData() {
        cRlInfo = CRLSetUpData.getCRLInfo(CRLStatus.LATEST, true);

        caEntityData = CRLSetUpData.getCAEntityData();

        certificateData = new CertificateData();
        certificateData.setSerialNumber(CommonConstants.VALID_CERTIFICATE_SERIALNUMBER);

        certAuthorityData = new CertificateAuthorityData();

        crlInfoData = new CRLInfoData();
        crlInfoData.setNextUpdate(new Date());
        crlInfoData.setCertificateData(certificateData);

        crlInfoDatas.add(crlInfoData);
        certAuthorityData.setcRLDatas(crlInfoDatas);
        caEntityData.setCertificateAuthorityData(certAuthorityData);

        caEntityData.getCertificateAuthorityData().setCertificateDatas(certificateDatas);

        caEntity = CRLSetUpData.getCaEntity(certificateAuthority);
        cAEntityDataForGetLatestCRL = CRLSetUpData.getCAEntityDataForCACertCRLInfoHashMap();

    }

    /**
     * Method to test Occurrence of CANotFoundException when CAEntityData is null
     *
     * @return Exception
     */

    @Test(expected = CANotFoundException.class)
    public void testGetCAEntity_CANotFoundException() {
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, CommonConstants.CA_NAME, Constants.CA_NAME_PATH)).thenReturn(null);
        cRLPersistenceHandler.getCAEntity(CommonConstants.CA_NAME);
    }

    /**
     * Method to test getCAEntity.
     */

    @Test
    public void testGetCAEntity() {
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, CommonConstants.CA_NAME, Constants.CA_NAME_PATH)).thenReturn(caEntityData);
        Mockito.when(caEntityMapper.toAPIFromModel(caEntityData)).thenReturn(caEntity);
        CAEntity ExpectedcaEntity = cRLPersistenceHandler.getCAEntity(CommonConstants.CA_NAME);
        assertNotNull(ExpectedcaEntity);
        assertEquals(ExpectedcaEntity, caEntity);
        assertEquals(ExpectedcaEntity.getCertificateAuthority(), caEntity.getCertificateAuthority());
        assertEquals(ExpectedcaEntity.getType(), caEntity.getType());

    }

    /**
     * Method to test Occurrence of CRLServiceException.
     *
     * @throws IOException.
     */
    @Test
    public void testGetCAEntity_CRLServiceException() throws IOException {
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, CommonConstants.CA_NAME, Constants.CA_NAME_PATH)).thenReturn(caEntityData);
        Mockito.doThrow(new PersistenceException(ErrorMessages.INTERNAL_ERROR)).when(caEntityMapper).toAPIFromModel(caEntityData);
        try {
            cRLPersistenceHandler.getCAEntity(CommonConstants.CA_NAME);
            fail("testGetCAEntity_CRLServiceException() should throw CRLServiceException");
        } catch (CRLServiceException cRLServiceException) {
            assertTrue(cRLServiceException.getMessage().contains(ErrorMessages.INTERNAL_ERROR));
        }
    }

    /**
     * Method to test updateCRLStatus.
     */
    @Test
    public void testUpdateCRLStatus() {
        CRLInfoData crlInfoData = new CRLInfoData();
        Mockito.when(crlInfoMapper.fromAPIToModel(cRlInfo, OperationType.UPDATE)).thenReturn(crlInfoData);
        cRLPersistenceHandler.updateCRLStatus(cRlInfo);
        Mockito.verify(persistenceManager).updateEntity(crlInfoData);
    }

    @Test(expected = CRLServiceException.class)
    public void testUpdateCRLStatus_CRLServiceException() {
        CRLInfoData crlInfoData = new CRLInfoData();
        Mockito.when(crlInfoMapper.fromAPIToModel(cRlInfo, OperationType.UPDATE)).thenReturn(crlInfoData);
        Mockito.when(persistenceManager.updateEntity(crlInfoData)).thenThrow(new PersistenceException());
        cRLPersistenceHandler.updateCRLStatus(cRlInfo);
    }

    @Test
    public void updateCRLStatusToExpired() {
        List<CRLInfoData> crlInfoDataList = new ArrayList<CRLInfoData>();

        CRLInfoData crlInfoData = new CRLInfoData();
        crlInfoDataList.add(crlInfoData);
        final HashMap<String, Object> parameters = new HashMap<String, Object>();
        parameters.put(CRL_STATUS, CRLStatus.LATEST);
        Mockito.when(persistenceManager.findEntitiesByAttributes(CRLInfoData.class, parameters)).thenReturn(crlInfoDataList);
        Mockito.when(crlInfoMapper.fromAPIToModel(cRlInfo, OperationType.UPDATE)).thenReturn(crlInfoData);
        final List<CACertificateIdentifier> cACertificateIdentifier = cRLPersistenceHandler.updateCRLStatusToExpired();

        assertNotNull(cACertificateIdentifier);
    }

    @Test
    public void getCACertificateIdentifierByCRL() {

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createNativeQuery(Mockito.anyString())).thenReturn(query);
        final CACertificateIdentifier cACertificateIdentifier = cRLPersistenceHandler.getCACertificateIdentifierByCRL(cRlInfo);
        assertNotNull(cACertificateIdentifier);
    }

    @Test
    public void getAllCRLInfoByPublishedToCDPS() {
        final List<CRLInfoData> crlInfoDataList = new ArrayList<CRLInfoData>();

        final CRLInfoData crlInfoData = CRLSetUpData.getCRLInfoData();

        crlInfoDataList.add(crlInfoData);
        final HashMap<String, Object> parameters = new HashMap<String, Object>();
        parameters.put(CRL_STATUS, CRLStatus.LATEST);
        Mockito.when(persistenceManager.findEntitiesByAttributes(CRLInfoData.class, parameters)).thenReturn(crlInfoDataList);
        final List<CRLInfo> crlInfoList = cRLPersistenceHandler.getAllCRLInfoByPublishedToCDPS(true);

        assertNotNull(crlInfoList);
    }

    @Test
    public void getCRLsToPublishToCDPS() {
        final List<CRLInfo> crlInfoList = cRLPersistenceHandler.getCRLsToPublishToCDPS();
        assertNotNull(crlInfoList);
    }

    @Test
    public void updateCAEnity() {
        final CAEntityData updateCaEntityData = CRLSetUpData.getCAEntityData();
        Mockito.when(caEntityMapper.fromAPIToModel(caEntity)).thenReturn(updateCaEntityData);
        Mockito.when(caEntityPersistenceHandler.findAndMergeEntityData(updateCaEntityData)).thenReturn(updateCaEntityData);
        Mockito.when(persistenceManager.updateEntity(updateCaEntityData)).thenReturn(updateCaEntityData);
        cRLPersistenceHandler.updateCAEnity(caEntity, true);
    }

    @Test(expected = CRLServiceException.class)
    public void updateCAEnity_ServiceException() {
        final CAEntityData updateCaEntityData = CRLSetUpData.getCAEntityData();
        Mockito.when(caEntityMapper.fromAPIToModel(caEntity)).thenReturn(updateCaEntityData);
        Mockito.when(caEntityPersistenceHandler.findAndMergeEntityData(updateCaEntityData)).thenReturn(updateCaEntityData);
        Mockito.when(persistenceManager.updateEntity(updateCaEntityData)).thenThrow(new PersistenceException());
        cRLPersistenceHandler.updateCAEnity(caEntity, true);
    }

    @Test(expected = CRLServiceException.class)
    public void getCRLInfoList_ServiceException() {
        final CAEntityData updateCaEntityData = CRLSetUpData.getCAEntityData();
        Map<String, Object> testmap = new HashMap<String, Object>();
        Mockito.when(persistenceManager.findEntitiesByAttributes(CRLInfoData.class, testmap)).thenThrow(new PersistenceException());
        cRLPersistenceHandler.getCRLInfoList(testmap);
    }

    @Test(expected = CANotFoundException.class)
    public void deleteInvalidCRLs_CANotFoundException() {

        CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();
        caCertificateIdentifier.setCaName("test");
        caCertificateIdentifier.setCerficateSerialNumber("214564564434534");
        List<CACertificateIdentifier> caCertificateIdentifiers = new ArrayList<CACertificateIdentifier>();
        caCertificateIdentifiers.add(caCertificateIdentifier);
        Map<String, Object> testmap = new HashMap<String, Object>();
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, caCertificateIdentifier.getCaName(), Constants.CA_NAME_PATH)).thenThrow(new PersistenceException());
        cRLPersistenceHandler.deleteInvalidCRLs(caCertificateIdentifiers);
    }

    @Test(expected = CANotFoundException.class)
    public void deleteCRLInfo_CANotFoundException() {

        CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();
        caCertificateIdentifier.setCaName("test");
        caCertificateIdentifier.setCerficateSerialNumber("214564564434534");
        List<CACertificateIdentifier> caCertificateIdentifiers = new ArrayList<CACertificateIdentifier>();
        caCertificateIdentifiers.add(caCertificateIdentifier);
        Map<String, Object> testmap = new HashMap<String, Object>();
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, caCertificateIdentifier.getCaName(), Constants.CA_NAME_PATH)).thenReturn(caEntityData);
        Mockito.doThrow(new EntityNotFoundException()).when(persistenceManager).refresh(caEntityData);
        cRLPersistenceHandler.deleteInvalidCRLs(caCertificateIdentifiers);
    }

    @Test(expected = CRLServiceException.class)
    public void deleteCRLInfo_CRLServiceException() {

        CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();
        caCertificateIdentifier.setCaName("test");
        caCertificateIdentifier.setCerficateSerialNumber("214564564434534");
        List<CACertificateIdentifier> caCertificateIdentifiers = new ArrayList<CACertificateIdentifier>();
        caCertificateIdentifiers.add(caCertificateIdentifier);
        Map<String, Object> testmap = new HashMap<String, Object>();
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, caCertificateIdentifier.getCaName(), Constants.CA_NAME_PATH)).thenReturn(caEntityData);
        Mockito.doThrow(new TransactionRequiredException()).when(persistenceManager).refresh(caEntityData);
        cRLPersistenceHandler.deleteInvalidCRLs(caCertificateIdentifiers);
    }

    @Test
    public void testDeleteInvalidCRLs() {
        final List<CACertificateIdentifier> caCertificateIdentifiers = new ArrayList<CACertificateIdentifier>();
        final CACertificateIdentifier caCertificateIdentifier = CRLSetUpData.getCACertificateIdentifier("RootCA", CommonConstants.VALID_CERTIFICATE_SERIALNUMBER);
        caCertificateIdentifiers.add(caCertificateIdentifier);

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, caCertificateIdentifier.getCaName(), Constants.CA_NAME_PATH)).thenReturn(caEntityData);

        cRLPersistenceHandler.deleteInvalidCRLs(caCertificateIdentifiers);

    }

    @Test
    public void testGetRequiredCACertIds() {
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createNativeQuery(Mockito.anyString())).thenReturn(query);
        cRLPersistenceHandler.getRequiredCACertIds();

        Mockito.verify(logger).debug("End Of getRequiredCACertIds method ");

    }

    @Test
    public void testGetOverlapPeriodForCRL() {
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createNativeQuery(Mockito.anyString())).thenReturn(query);
        cRLPersistenceHandler.getOverlapPeriodForCRL(cRlInfo);
    }

    @Test(expected = CRLServiceException.class)
    public void testupdateCAEnityPersistenceException() {
        final CAEntityData updateCaEntityData = CRLSetUpData.getCAEntityData();
        Mockito.when(caEntityMapper.fromAPIToModel(caEntity)).thenReturn(updateCaEntityData);
        Mockito.when(caEntityPersistenceHandler.findAndMergeEntityData(updateCaEntityData)).thenReturn(updateCaEntityData);
        Mockito.when(persistenceManager.updateEntity(updateCaEntityData)).thenThrow(new PersistenceException());
        cRLPersistenceHandler.updateCAEnity(caEntity, true);
    }

    @Test(expected = CRLServiceException.class)
    public void testGetCRLInfoListPersistenceException() {
        final HashMap<String, Object> parameters = new HashMap<String, Object>();
        Mockito.when(persistenceManager.findEntitiesByAttributes(CRLInfoData.class, parameters)).thenThrow(new PersistenceException());

        cRLPersistenceHandler.getCRLInfoList(parameters);
    }

    @Test(expected = CANotFoundException.class)
    public void testDeleteInvalidCRLs_PersistenceException() {

        final List<CACertificateIdentifier> caCertificateIdentifiers = new ArrayList<CACertificateIdentifier>();
        final CACertificateIdentifier caCertificateIdentifier = CRLSetUpData.getCACertificateIdentifier("RootCA", CommonConstants.VALID_CERTIFICATE_SERIALNUMBER);
        caCertificateIdentifiers.add(caCertificateIdentifier);
        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, caCertificateIdentifier.getCaName(), Constants.CA_NAME_PATH)).thenThrow(new CANotFoundException("CA Entity Not Found"));
        cRLPersistenceHandler.deleteInvalidCRLs(caCertificateIdentifiers);
    }

    @Test
    public void testUpdateLatestCRL() {
        Map<CACertificateIdentifier, CRLInfo> caCrlInfoHashMapToUpdate = new HashMap<CACertificateIdentifier, CRLInfo>();
        CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();
        CACertificateIdentifier caCertificateIdentifier1 = new CACertificateIdentifier();
        caCertificateIdentifier.setCaName("ENM_ROOT_CA");
        caCertificateIdentifier.setCerficateSerialNumber("12345");
        caCrlInfoHashMapToUpdate.put(caCertificateIdentifier1, cRlInfo);
        Map<CACertificateIdentifier, CRLInfo> caCrlInfoHashMapToSet = new HashMap<CACertificateIdentifier, CRLInfo>();
        caCrlInfoHashMapToSet.put(caCertificateIdentifier, cRlInfo);

        cRLPersistenceHandler.updateLatestCRL(caCrlInfoHashMapToUpdate, caCrlInfoHashMapToSet);
    }

    @Test
    public void testUpdateLatestCRLSaveNew() {
        Map<CACertificateIdentifier, CRLInfo> caCrlInfoHashMapToUpdate = new HashMap<CACertificateIdentifier, CRLInfo>();
        CACertificateIdentifier caCertificateIdentifier = new CACertificateIdentifier();
        caCertificateIdentifier.setCaName("ENM_ROOT_CA");
        caCertificateIdentifier.setCerficateSerialNumber("12345");
        caCrlInfoHashMapToUpdate.put(caCertificateIdentifier, null);
        Map<CACertificateIdentifier, CRLInfo> caCrlInfoHashMapToSet = new HashMap<CACertificateIdentifier, CRLInfo>();
        caCrlInfoHashMapToSet.put(caCertificateIdentifier, cRlInfo);

        Mockito.when(persistenceManager.findEntityByName(CAEntityData.class, "ENM_ROOT_CA", Constants.CA_NAME_PATH)).thenReturn(caEntityData);

        cRLPersistenceHandler.updateLatestCRL(caCrlInfoHashMapToUpdate, caCrlInfoHashMapToSet);
    }

    @Test
    public void testGetCACertCRLInfoHashMap() {
        mockEntityManagerCalls();
        Mockito.when(crlInfoMapper.toAPIFromModel(Mockito.any(CRLInfoData.class))).thenReturn(new CRLInfo());

        final Map<CACertificateIdentifier, CRLInfo> caCertCRLInfoMap = cRLPersistenceHandler.getCACertCRLInfoMap();

        assertCACertCRLInfoMap(caCertCRLInfoMap, false);
    }

    @Test
    public void testGetCACertCRLInfoHashMap_With_No_CRLInfo() {
        mockEntityManagerCalls();
        cAEntityDataForGetLatestCRL.getCertificateAuthorityData().setcRLDatas(null);

        final Map<CACertificateIdentifier, CRLInfo> caCertCRLInfoMap = cRLPersistenceHandler.getCACertCRLInfoMap();

        assertCACertCRLInfoMap(caCertCRLInfoMap, true);

    }

    @Test
    public void testGetCACertCRLInfoHashMap_With_NO_CRLGenerationInfo() {
        mockEntityManagerCalls();
        cAEntityDataForGetLatestCRL.getCertificateAuthorityData().setCrlGenerationInfo(null);
        final Map<CACertificateIdentifier, CRLInfo> caCertCRLInfoMap = cRLPersistenceHandler.getCACertCRLInfoMap();

        Mockito.verify(logger).info(String.format(ErrorMessages.UNABLE_TO_FETCH_LATEST_CRL, CommonConstants.CA_NAME, "the CA doesn't have CRLGenerationInfo."));
        assertTrue(ValidationUtils.isNullOrEmpty(caCertCRLInfoMap));
    }

    private void mockEntityManagerCalls() {
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(Mockito.anyString())).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(Arrays.asList(cAEntityDataForGetLatestCRL));
    }

    private void assertCACertCRLInfoMap(final Map<CACertificateIdentifier, CRLInfo> caCertCRLInfoMap, final boolean noCRLInfo) {
        assertFalse(ValidationUtils.isNullOrEmpty(caCertCRLInfoMap));
        CACertificateIdentifier caCertId = new CACertificateIdentifier(CommonConstants.CA_NAME, CommonConstants.VALID_CERTIFICATE_SERIALNUMBER);
        assertTrue(caCertCRLInfoMap.containsKey(caCertId));
        if (noCRLInfo) {
            assertNull(caCertCRLInfoMap.get(caCertId));
        } else {
            assertNotNull(caCertCRLInfoMap.get(caCertId));
        }
        caCertId.setCerficateSerialNumber(CommonConstants.VALID_CERTIFICATE_WITH_ISSUER_REVOKED_SERIALNUMBER);
        assertFalse(caCertCRLInfoMap.containsKey(caCertId));
    }
}
