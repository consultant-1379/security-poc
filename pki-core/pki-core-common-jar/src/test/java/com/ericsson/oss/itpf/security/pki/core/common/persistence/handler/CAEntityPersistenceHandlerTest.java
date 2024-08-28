/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.core.common.persistence.handler;

import java.text.ParseException;
import java.text.SimpleDateFormat;
import java.util.*;

import javax.persistence.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CertificateAuthorityModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateData;
import com.ericsson.oss.itpf.security.pki.core.common.utils.OperationType;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;

@RunWith(MockitoJUnitRunner.class)
public class CAEntityPersistenceHandlerTest {

    @InjectMocks
    CAEntityPersistenceHandler caEntityPersistenceHandler;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    Logger logger;

    @Mock
    Query typeQuery;

    @Mock
    Query typeQuery1;

    @Mock
    EntityManager entityManager;

    @Mock
    CertificateAuthorityModelMapper cAEntityMapper;

    private CertificateAuthority certificateAuthority;

    private CertificateAuthorityData certificateAuthorityData;

    private CertificateData certificateData;

    private String query = "select cd from CertificateAuthorityData cd where cd.issuerCA.id in (select ca.id from CertificateAuthorityData ca where ca.name=:name ))";

    @Before
    public void setUp() {
        certificateAuthority = new CertificateAuthority();
        certificateAuthority.setId(123);
        certificateAuthority.setName("ABC");
        certificateAuthority.setRootCA(true);
        certificateAuthority.setStatus(CAStatus.ACTIVE);

        certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setId(123);
        certificateAuthorityData.setName("ABC");
        certificateAuthorityData.setRootCA(true);
        certificateAuthorityData.setStatus(CAStatus.ACTIVE);
    }

    @Test
    public void testPersistCA() {
        final CertificateAuthorityData authorityData = new CertificateAuthorityData();
        Mockito.when(cAEntityMapper.fromAPIModel(certificateAuthority, OperationType.CREATE)).thenReturn(authorityData);
        Mockito.doNothing().when(persistenceManager).createEntity(authorityData);
        caEntityPersistenceHandler.persistCA(certificateAuthority);
        Mockito.verify(cAEntityMapper).fromAPIModel(certificateAuthority, OperationType.CREATE);
        Mockito.verify(persistenceManager).createEntity(authorityData);
    }

    @Test
    public void testpersistCertificateAuthorityData() {

        final CertificateAuthorityData authorityData = new CertificateAuthorityData();
        Mockito.doNothing().when(persistenceManager).createEntity(authorityData);
        caEntityPersistenceHandler.persistCertificateAuthorityData(authorityData);
        Mockito.verify(persistenceManager).createEntity(authorityData);
    }

    @Test(expected = CoreEntityAlreadyExistsException.class)
    public void testpersistCertificateAuthorityData_EntityExistsException() {

        final CertificateAuthorityData authorityData = new CertificateAuthorityData();
        Mockito.doThrow(new EntityExistsException()).when(persistenceManager).createEntity(authorityData);
        caEntityPersistenceHandler.persistCertificateAuthorityData(authorityData);
        Mockito.verify(persistenceManager).createEntity(authorityData);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testpersistCertificateAuthorityData_EntityServiceException() {

        final CertificateAuthorityData authorityData = new CertificateAuthorityData();
        Mockito.doThrow(new TransactionRequiredException()).when(persistenceManager).createEntity(authorityData);
        caEntityPersistenceHandler.persistCertificateAuthorityData(authorityData);
        Mockito.verify(persistenceManager).createEntity(authorityData);
    }

    @Test(expected = CoreEntityAlreadyExistsException.class)
    public void testPersistCA_EntityExistsException() {
        final CertificateAuthorityData authorityData = new CertificateAuthorityData();
        Mockito.when(cAEntityMapper.fromAPIModel(certificateAuthority, OperationType.CREATE)).thenReturn(authorityData);
        Mockito.doThrow(new EntityExistsException()).when(persistenceManager).createEntity(authorityData);
        caEntityPersistenceHandler.persistCA(certificateAuthority);
        Mockito.verify(cAEntityMapper).fromAPIModel(certificateAuthority, OperationType.CREATE);
        Mockito.verify(persistenceManager).createEntity(authorityData);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testPersistCA_TransactionRequiredException() {
        final CertificateAuthorityData authorityData = new CertificateAuthorityData();
        Mockito.when(cAEntityMapper.fromAPIModel(certificateAuthority, OperationType.CREATE)).thenReturn(authorityData);
        Mockito.doThrow(new TransactionRequiredException()).when(persistenceManager).createEntity(authorityData);
        caEntityPersistenceHandler.persistCA(certificateAuthority);
        Mockito.verify(cAEntityMapper).fromAPIModel(certificateAuthority, OperationType.CREATE);
        Mockito.verify(persistenceManager).createEntity(authorityData);
    }

    @Test
    public void testUpdateCA() {
        final CertificateAuthorityData authorityData = new CertificateAuthorityData();
        Mockito.when(cAEntityMapper.fromAPIModel(certificateAuthority, OperationType.UPDATE)).thenReturn(authorityData);
        caEntityPersistenceHandler.updateCA(certificateAuthority);
        Mockito.verify(cAEntityMapper).fromAPIModel(certificateAuthority, OperationType.UPDATE);
    }

    @Test
    public void testUpdateCertificateStatus() {
        testUpdateCertificateStatus_Setup(true);
        Mockito.doNothing().when(persistenceManager).updateCertificateStatus(certificateData.getId(), CertificateStatus.INACTIVE.getId());
        caEntityPersistenceHandler.updateCertificateStatus(certificateAuthorityData, CAStatus.ACTIVE);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testUpdateCertificateStatus_TransactionRequiredException() {
        testUpdateCertificateStatus_Setup(true);
        Mockito.doThrow(new TransactionRequiredException()).when(persistenceManager).updateEntity(certificateData);
        caEntityPersistenceHandler.updateCertificateStatus(certificateAuthorityData, CAStatus.ACTIVE);
    }

    @Test
    public void testUpdateCertificateStatus_CertificateDataStatus_ACTIVE() {
        testUpdateCertificateStatus_Setup(false);
        Mockito.doNothing().when(persistenceManager).updateCertificateStatus(certificateData.getId(), CertificateStatus.INACTIVE.getId());
        caEntityPersistenceHandler.updateCertificateStatus(certificateAuthorityData, CAStatus.INACTIVE);
    }

    @Test
    public void testDeleteCA() {
        Mockito.doNothing().when(persistenceManager).deleteEntity(certificateAuthorityData);
        caEntityPersistenceHandler.deleteCA(certificateAuthorityData);
        Mockito.verify(persistenceManager).deleteEntity(certificateAuthorityData);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void test_UpdateCA() {
        final CertificateAuthorityData authorityData = new CertificateAuthorityData();
        Mockito.when(cAEntityMapper.fromAPIModel(certificateAuthority, OperationType.UPDATE)).thenReturn(authorityData);
        Mockito.doThrow(new TransactionRequiredException()).when(persistenceManager).updateEntity(authorityData);
        caEntityPersistenceHandler.updateCA(certificateAuthority);
        // Mockito.verify(persistenceManager).deleteEntity(certificateAuthorityData);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testDeleteCA_EntityServiceException() {
        Mockito.doThrow(new TransactionRequiredException()).when(persistenceManager).deleteEntity(certificateAuthorityData);
        caEntityPersistenceHandler.deleteCA(certificateAuthorityData);
        Mockito.verify(persistenceManager).deleteEntity(certificateAuthorityData);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testDeleteCA_PersistenceException() {
        Mockito.doThrow(new PersistenceException()).when(persistenceManager).deleteEntity(certificateAuthorityData);
        caEntityPersistenceHandler.deleteCA(certificateAuthorityData);
        Mockito.verify(persistenceManager).deleteEntity(certificateAuthorityData);
    }

    @Test(expected = Exception.class)
    public void testGetCAData_EntityNotFoundException() {
        final Map<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("id", certificateAuthority.getId());
        parameters.put("name", certificateAuthority.getName());
        final List<CertificateAuthorityData> caDataList = new ArrayList<CertificateAuthorityData>();

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateAuthorityData.class, parameters)).thenReturn(caDataList);
        certificateAuthorityData = caEntityPersistenceHandler.getCAData(certificateAuthority);
        Mockito.verify(persistenceManager).findEntitiesByAttributes(CertificateAuthorityData.class, parameters);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testGetCADataPersistanceException() {
        final Map<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("id", certificateAuthority.getId());
        parameters.put("name", certificateAuthority.getName());
        final List<CertificateAuthorityData> caDataList = new ArrayList<CertificateAuthorityData>();

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateAuthorityData.class, parameters)).thenThrow(new CoreEntityServiceException());
        certificateAuthorityData = caEntityPersistenceHandler.getCAData(certificateAuthority);
        Mockito.verify(persistenceManager).findEntitiesByAttributes(CertificateAuthorityData.class, parameters);
    }

    @Test(expected = Exception.class)
    public void testGetCAData_CertificateAuthority_ID_ZERO() {
        final Map<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("id", 0);
        parameters.put("name", "ABC");
        certificateAuthority.setId(0);

        final List<CertificateAuthorityData> caDataList = new ArrayList<CertificateAuthorityData>();

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateAuthorityData.class, parameters)).thenReturn(caDataList);

        certificateAuthorityData = caEntityPersistenceHandler.getCAData(certificateAuthority);

        Mockito.verify(persistenceManager).findEntitiesByAttributes(CertificateAuthorityData.class, parameters);
    }

    @Test(expected = Exception.class)
    public void testGetCAData_CertificateAuthority_NAME_EMPTY() {
        final Map<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("id", 1);
        parameters.put("name", "ABC");
        certificateAuthority.setId(1);
        certificateAuthority.setName("");

        final List<CertificateAuthorityData> caDataList = new ArrayList<CertificateAuthorityData>();

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateAuthorityData.class, parameters)).thenReturn(caDataList);

        certificateAuthorityData = caEntityPersistenceHandler.getCAData(certificateAuthority);
        Mockito.verify(persistenceManager).findEntitiesByAttributes(CertificateAuthorityData.class, parameters);
    }

    @Test(expected = Exception.class)
    public void testGetCAData_Empty_Parameter() {
        final Map<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("id", 0);
        parameters.put("name", "");
        certificateAuthority.setId(0);
        certificateAuthority.setName("");

        final List<CertificateAuthorityData> caDataList = new ArrayList<CertificateAuthorityData>();

        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateAuthorityData.class, parameters)).thenReturn(caDataList);

        certificateAuthorityData = caEntityPersistenceHandler.getCAData(certificateAuthority);

        Mockito.verify(persistenceManager).findEntitiesByAttributes(CertificateAuthorityData.class, parameters);
    }

    @Test
    public void testGetSubCAsUnderCA() {
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(persistenceManager.getEntityManager().createQuery(query)).thenReturn(typeQuery);
        final List<CertificateAuthorityData> list = caEntityPersistenceHandler.getSubCAsUnderCA("ABC");
        Mockito.verify(persistenceManager.getEntityManager()).createQuery(query);
    }

    @Test(expected = CoreEntityInUseException.class)
    public void testCheckEntityUnderCA() {
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(
                persistenceManager.getEntityManager().createQuery(
                        "select count(*) from EntityInfoData e where e.status=2 and e.issuerCA.id in (select ed.id from CertificateAuthorityData ed where name=:name)")).thenReturn(typeQuery);
        Mockito.when(typeQuery.getSingleResult()).thenReturn(new Long(1));
        caEntityPersistenceHandler.checkEntityUnderCA("ABC");
    }

    @Test
    public void testGetAllCAsByStatus() {
        final Map<String, Object> parameters = new HashMap<String, Object>();
        parameters.put("status", CAStatus.ACTIVE);
        final List<CertificateAuthorityData> caDataList = new ArrayList<CertificateAuthorityData>();
        Mockito.when(persistenceManager.findEntitiesByAttributes(CertificateAuthorityData.class, parameters)).thenReturn(caDataList);
        caEntityPersistenceHandler.getAllCAsByStatus(CAStatus.ACTIVE);
        Mockito.verify(persistenceManager).findEntitiesByAttributes(CertificateAuthorityData.class, parameters);
    }

    @Test
    public void testCheckSubCAsUnderCA() {
        final List<CertificateAuthorityData> subCAList = testCheckSubCAsUnderCA_setup(CAStatus.INACTIVE, true);
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(
                persistenceManager.getEntityManager().createQuery(
                        "select cd from CertificateAuthorityData cd where cd.issuerCA.id in (select ca.id from CertificateAuthorityData ca where ca.name=:name ))")).thenReturn(typeQuery);
        caEntityPersistenceHandler.checkSubCAsUnderCA(subCAList);
        Mockito.verify(persistenceManager.getEntityManager()).createQuery(
                "select cd from CertificateAuthorityData cd where cd.issuerCA.id in (select ca.id from CertificateAuthorityData ca where ca.name=:name ))");
    }

    @Test
    public void testCheckSubCAsUnderCA_1() {
        final List<CertificateAuthorityData> subCAList = testCheckSubCAsUnderCA_setup(CAStatus.INACTIVE, false);
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(
                persistenceManager.getEntityManager().createQuery(
                        "select cd from CertificateAuthorityData cd where cd.issuerCA.id in (select ca.id from CertificateAuthorityData ca where ca.name=:name ))")).thenReturn(typeQuery);
        Mockito.when(
                persistenceManager.getEntityManager().createQuery(
                        "select count(*) from EntityInfoData e where e.status=2 and e.issuerCA.id in (select ed.id from CertificateAuthorityData ed where name=:name)")).thenReturn(typeQuery1);
        Mockito.when(typeQuery.getSingleResult()).thenReturn(new Long(1));
        Mockito.when(typeQuery1.getSingleResult()).thenReturn(new Long(0));
        caEntityPersistenceHandler.checkSubCAsUnderCA(subCAList);
        Mockito.verify(persistenceManager.getEntityManager()).createQuery(
                "select cd from CertificateAuthorityData cd where cd.issuerCA.id in (select ca.id from CertificateAuthorityData ca where ca.name=:name ))");
        Mockito.verify(persistenceManager.getEntityManager()).createQuery(
                "select count(*) from EntityInfoData e where e.status=2 and e.issuerCA.id in (select ed.id from CertificateAuthorityData ed where name=:name)");
    }

    @Test(expected = CoreEntityInUseException.class)
    public void testCheckSubCAsUnderCA_Status_ACTIVE_EntityInUseException() {
        final List<CertificateAuthorityData> subCAList = testCheckSubCAsUnderCA_setup(CAStatus.ACTIVE, false);
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(
                persistenceManager.getEntityManager().createQuery(
                        "select cd from CertificateAuthorityData cd where cd.issuerCA.id in (select ca.id from CertificateAuthorityData ca where ca.name=:name ))")).thenReturn(typeQuery);
        Mockito.when(
                persistenceManager.getEntityManager().createQuery(
                        "select count(*) from EntityData e where e.status=2 and e.issuerCA.id in (select ed.id from CertificateAuthorityData ed where name=:name)")).thenReturn(typeQuery1);
        Mockito.when(typeQuery.getSingleResult()).thenReturn(new Long(1));
        Mockito.when(typeQuery1.getSingleResult()).thenReturn(new Long(0));
        caEntityPersistenceHandler.checkSubCAsUnderCA(subCAList);
        Mockito.verify(persistenceManager.getEntityManager()).createQuery(
                "select cd from CertificateAuthorityData cd where cd.issuerCA.id in (select ca.id from CertificateAuthorityData ca where ca.name=:name ))");
        Mockito.verify(persistenceManager.getEntityManager()).createQuery(
                "select count(*) from EntityData e where e.status=2 and e.issuerCA.id in (select ed.id from CertificateAuthorityData ed where name=:name)");
    }

    private List<CertificateAuthorityData> testCheckSubCAsUnderCA_setup(CAStatus caStatus, boolean isRootCA) {
        final List<CertificateAuthorityData> subCAList = new ArrayList<CertificateAuthorityData>();
        certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setId(123);
        certificateAuthorityData.setName("ABC");
        certificateAuthorityData.setRootCA(isRootCA);
        certificateAuthorityData.setStatus(caStatus);
        subCAList.add(certificateAuthorityData);
        return subCAList;
    }

    private void testUpdateCertificateStatus_Setup(final boolean flag) {
        final Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
        certificateData = new CertificateData();
        certificateData.setId(987);
        certificateData.setSerialNumber("654");
        final SimpleDateFormat format = new SimpleDateFormat("yyyy-MM-DD");
        try {
            certificateData.setNotAfter(format.parse("2015-11-25"));
        } catch (ParseException e) {
            e.printStackTrace();
        }
        certificateData.setNotBefore(new Date());
        certificateDatas.add(certificateData);
        if (flag) {
            certificateAuthorityData.setStatus(CAStatus.INACTIVE);
            certificateData.setStatus(CertificateStatus.INACTIVE);
        } else {
            certificateAuthorityData.setStatus(CAStatus.ACTIVE);
            certificateData.setStatus(CertificateStatus.ACTIVE);
        }
        certificateAuthorityData.setCertificateDatas(certificateDatas);
    }
}
