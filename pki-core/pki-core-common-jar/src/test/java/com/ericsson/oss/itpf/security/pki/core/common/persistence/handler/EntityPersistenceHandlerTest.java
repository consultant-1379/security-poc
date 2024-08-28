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

import java.util.*;

import javax.persistence.*;

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.core.common.constants.EntityManagementErrorCodes;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CertificateAuthorityModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.EntityModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.EntityInfoData;
import com.ericsson.oss.itpf.security.pki.core.common.utils.OperationType;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;

@RunWith(MockitoJUnitRunner.class)
public class EntityPersistenceHandlerTest {

    @InjectMocks
    EntityPersistenceHandler entityPersistenceHandler;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    Logger logger;

    @Mock
    EntityManager entityManager;

    @Mock
    EntityModelMapper entityModelMapper;

    @Mock
    CertificateAuthorityModelMapper cAEntityMapper;

    private EntityInfo entityInfo;

    private EntityInfoData entityInfoData;

    @Before
    public void setUp() {
        entityInfo = new EntityInfo();
        entityInfo.setId(123);
        entityInfo.setName("ABC");

        entityInfoData = new EntityInfoData();
        entityInfoData.setId(123);
        entityInfoData.setName("ABC");

    }

    @Test
    public void persistEntityInfo() {
        final EntityInfoData entityInfoData = new EntityInfoData();
        Mockito.when(entityModelMapper.fromAPIToModel(entityInfo, OperationType.CREATE)).thenReturn(entityInfoData);
        Mockito.doNothing().when(persistenceManager).createEntity(entityInfoData);
        entityPersistenceHandler.persistEntityInfo(entityInfoData);
        Mockito.verify(persistenceManager).createEntity(entityInfoData);
    }

    @Test
    public void persistEntity() {
        final EntityInfo entityInfo = new EntityInfo();
        Mockito.when(entityModelMapper.fromAPIToModel(entityInfo, OperationType.CREATE)).thenReturn(entityInfoData);
        Mockito.doNothing().when(persistenceManager).createEntity(entityInfoData);
        entityPersistenceHandler.persistEntity(entityInfo);
        Mockito.verify(persistenceManager).createEntity(entityInfoData);
    }

    @Test(expected = CoreEntityAlreadyExistsException.class)
    public void persistEntityInfo_EntityServiceException() {
        final EntityInfo entityInfo = new EntityInfo();
        Mockito.doThrow(new javax.persistence.EntityExistsException(EntityManagementErrorCodes.ENTITY_ALREADY_EXISTS)).when(persistenceManager).createEntity(entityInfoData);
        Mockito.when(entityModelMapper.fromAPIToModel(entityInfo, OperationType.CREATE)).thenReturn(entityInfoData);
        entityPersistenceHandler.persistEntity(entityInfo);
        Mockito.verify(persistenceManager).createEntity(entityInfoData);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void persistEntityInfo_PersistenceServiceException() {
        final EntityInfo entityInfo = new EntityInfo();
        Mockito.doThrow(new javax.persistence.PersistenceException()).when(persistenceManager).createEntity(entityInfoData);
        Mockito.when(entityModelMapper.fromAPIToModel(entityInfo, OperationType.CREATE)).thenReturn(entityInfoData);
        entityPersistenceHandler.persistEntity(entityInfo);
        Mockito.verify(persistenceManager).createEntity(entityInfoData);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void persistEntityInfo_EntityAlreadyException() {
        final EntityInfo entityInfo = new EntityInfo();
        Mockito.doThrow(new TransactionRequiredException()).when(persistenceManager).createEntity(entityInfoData);
        Mockito.when(entityModelMapper.fromAPIToModel(entityInfo, OperationType.CREATE)).thenReturn(entityInfoData);
        entityPersistenceHandler.persistEntity(entityInfo);
        Mockito.verify(persistenceManager).createEntity(entityInfoData);
    }

    @Test(expected = CoreEntityAlreadyExistsException.class)
    public void persistEntity_EntityServiceException() {
        final EntityInfoData entityInfoData = new EntityInfoData();
        Mockito.doThrow(new javax.persistence.EntityExistsException(EntityManagementErrorCodes.ENTITY_ALREADY_EXISTS)).when(persistenceManager).createEntity(entityInfoData);
        entityPersistenceHandler.persistEntityInfo(entityInfoData);
        Mockito.verify(persistenceManager).createEntity(entityInfoData);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void persistEntity_EntityAlreadyException() {
        final EntityInfoData entityInfoData = new EntityInfoData();
        Mockito.doThrow(new TransactionRequiredException()).when(persistenceManager).createEntity(entityInfoData);
        Mockito.when(entityModelMapper.fromAPIToModel(entityInfo, OperationType.CREATE)).thenReturn(entityInfoData);
        entityPersistenceHandler.persistEntityInfo(entityInfoData);
        Mockito.verify(persistenceManager).createEntity(entityInfoData);
    }

    @Test
    public void testCheckEntityCanBeDeleted() {

        entityPersistenceHandler.checkEntityCanBeDeleted(EntityStatus.DELETED);
        Mockito.verify(logger, Mockito.atLeastOnce()).info("Entity is already deleted.");
    }

    @Test(expected = CoreEntityInUseException.class)
    public void testCheckEntityCanBeDeletedWithActiveState() {

        entityPersistenceHandler.checkEntityCanBeDeleted(EntityStatus.ACTIVE);

    }

    @Test(expected = CoreEntityInUseException.class)
    public void testCheckEntityCanBeDeletedWithReissueState() {

        entityPersistenceHandler.checkEntityCanBeDeleted(EntityStatus.REISSUE);

    }

    @Test
    public void testCheckEntityCanBeDeletedWithNewState() {

        Assert.assertTrue(entityPersistenceHandler.checkEntityCanBeDeleted(EntityStatus.NEW));

    }

    @Test
    public void testDeleteEntityWithStausNew() {

        entityInfoData.setStatus(EntityStatus.NEW);
        entityPersistenceHandler.deleteEntity(entityInfoData);
        Mockito.verify(logger, Mockito.atLeastOnce()).debug("Deleted {}", entityInfoData);
    }

    @Test
    public void testDeleteEntityWithStatusInactive() {

        entityInfoData.setStatus(EntityStatus.INACTIVE);
        entityPersistenceHandler.deleteEntity(entityInfoData);
        entityInfoData.setStatus(EntityStatus.DELETED);
        Mockito.verify(logger, Mockito.atLeastOnce()).debug("Deleted {}", entityInfoData);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testDeleteEntity_EntityServiceExceptionWithStatusNew() {

        entityInfoData.setStatus(EntityStatus.NEW);
        Mockito.doThrow(new PersistenceException()).when(persistenceManager).deleteEntity(Mockito.any());
        entityPersistenceHandler.deleteEntity(entityInfoData);

    }

    @Test(expected = CoreEntityServiceException.class)
    public void testDeleteEntity_EntityServiceExceptionWithStatusInactive() {

        Mockito.doThrow(new TransactionRequiredException()).when(persistenceManager).updateEntity(Mockito.any());
        entityInfoData.setStatus(EntityStatus.INACTIVE);
        entityPersistenceHandler.deleteEntity(entityInfoData);

    }

    @Test
    public void updateEntityTest() {
        final EntityInfo entityInfo = new EntityInfo();
        Mockito.when(entityModelMapper.fromAPIToModel(entityInfo, OperationType.UPDATE)).thenReturn(entityInfoData);
        Mockito.when(persistenceManager.updateEntity(entityInfoData)).thenReturn(entityInfoData);
        entityPersistenceHandler.updateEntity(entityInfo);
        Mockito.verify(persistenceManager).updateEntity(entityInfoData);
    }

    @Test
    public void updateCertificateStatusTest() {
        final CertificateData certificateData = new CertificateData();
        certificateData.setStatus(CertificateStatus.ACTIVE);

        certificateData.setNotAfter(new Date());
        final Set<CertificateData> certificateDatasSet = new HashSet<CertificateData>();
        certificateDatasSet.add(certificateData);
        entityInfoData.setCertificateDatas(certificateDatasSet);
        entityInfoData.setStatus(EntityStatus.ACTIVE);
        Mockito.doNothing().when(persistenceManager).updateCertificateStatus(certificateData.getId(), CertificateStatus.INACTIVE.getId());
        entityPersistenceHandler.updateCertificateStatus(entityInfoData, EntityStatus.INACTIVE);
    }

    /*
     * @Test(expected = CoreEntityServiceException.class) public void updateCertificateStatusTestException() { final CertificateData certificateData = new CertificateData();
     * certificateData.setStatus(CertificateStatus.ACTIVE);
     * 
     * certificateData.setNotAfter(new Date()); final Set<CertificateData> certificateDatasSet = new HashSet<CertificateData>(); certificateDatasSet.add(certificateData);
     * entityInfoData.setCertificateDatas(certificateDatasSet); entityInfoData.setStatus(EntityStatus.ACTIVE);
     * Mockito.when(persistenceManager.updateEntity(certificateData)).thenThrow(TransactionRequiredException.class); entityPersistenceHandler.updateCertificateStatus(entityInfoData,
     * EntityStatus.INACTIVE); }
     */

    @Test(expected = CoreEntityServiceException.class)
    public void updateEntity_EntityAlreadyException() {

        final EntityInfo entityInfo = new EntityInfo();
        Mockito.when(entityModelMapper.fromAPIToModel(entityInfo, OperationType.UPDATE)).thenReturn(entityInfoData);
        Mockito.when(persistenceManager.updateEntity(entityInfoData)).thenReturn(entityInfoData);

        Mockito.doThrow(new TransactionRequiredException()).when(persistenceManager).updateEntity(entityInfoData);
        entityPersistenceHandler.updateEntity(entityInfo);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void updateEntity_PersistenceException() {

        final EntityInfo entityInfo = new EntityInfo();
        Mockito.when(entityModelMapper.fromAPIToModel(entityInfo, OperationType.UPDATE)).thenReturn(entityInfoData);
        Mockito.when(persistenceManager.updateEntity(entityInfoData)).thenReturn(entityInfoData);

        Mockito.doThrow(new PersistenceException()).when(persistenceManager).updateEntity(entityInfoData);
        entityPersistenceHandler.updateEntity(entityInfo);
    }

    @Test(expected = CoreEntityNotFoundException.class)
    public void getEntityInfoDataTest() {

        entityPersistenceHandler.getEntityInfoData(entityInfo);

    }

    @Test(expected = IllegalArgumentException.class)
    public void getEntityInfoDataNullTest() {
        entityInfo.setName(null);
        entityInfo.setId(0);
        entityPersistenceHandler.getEntityInfoData(entityInfo);

    }

}
