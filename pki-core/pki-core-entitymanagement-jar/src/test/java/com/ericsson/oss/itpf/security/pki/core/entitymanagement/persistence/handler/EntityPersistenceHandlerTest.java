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
package com.ericsson.oss.itpf.security.pki.core.entitymanagement.persistence.handler;

import static org.mockito.Mockito.when;

import java.security.cert.CertificateException;
import java.util.*;

import javax.persistence.*;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.EntityModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.EntityInfoData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.EntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.common.utils.OperationType;
import com.ericsson.oss.itpf.security.pki.core.entitymanagement.common.utils.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException;

@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class EntityPersistenceHandlerTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(CAEntityPersistenceHandler.class);

    @InjectMocks
    EntityPersistenceHandler entityPersistenceHandler;

    @Mock
    EntityModelMapper entityMapper;

    @Mock
    PersistenceManager persistenceManager;

    EntityInfo entityInfo;
    EntityInfoData entityInfoData;

    long id;
    String name;

    @Before
    public void setUp() throws CertificateException {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();

        entityInfo = entitiesSetUpData.getEntityInfo();
        entityInfoData = entitiesSetUpData.getEntityInfoData();

        id = entityInfo.getId();
        name = entityInfo.getName();

        when(entityMapper.fromAPIToModel(entityInfo, OperationType.CREATE)).thenReturn(entityInfoData);

        when(persistenceManager.findEntityByName(EntityInfoData.class, name, EntitiesSetUpData.NAME_PATH)).thenReturn(entityInfoData);

        when(entityMapper.toAPIFromModel(entityInfoData)).thenReturn(entityInfo);

        when(persistenceManager.findEntityByIdAndName(EntityInfoData.class, id, name, EntitiesSetUpData.NAME_PATH)).thenReturn(entityInfoData);
    }

    @Test
    public void testCreateEntity() {

        entityPersistenceHandler.persistEntity(entityInfo);
    }

    @Test(expected = CoreEntityAlreadyExistsException.class)
    public void testCreateEntityExistsException() {

        Mockito.doThrow(new EntityExistsException()).when(persistenceManager).createEntity(entityInfoData);

        entityPersistenceHandler.persistEntity(entityInfo);

    }

    @Test(expected = CoreEntityServiceException.class)
    public void testCreateTransactionRequiredException() {

        Mockito.doThrow(new TransactionRequiredException()).when(persistenceManager).createEntity(entityInfoData);

        entityPersistenceHandler.persistEntity(entityInfo);

    }

    @Test
    public void testUpdateEntity() {

        when(entityMapper.fromAPIToModel(entityInfo, OperationType.UPDATE)).thenReturn(entityInfoData);
        when(persistenceManager.updateEntity(entityInfoData)).thenReturn(null);

        entityPersistenceHandler.persistEntity(entityInfo);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testUpdateEntityTransactionRequiredException() {

        when(entityMapper.fromAPIToModel(entityInfo, OperationType.UPDATE)).thenReturn(entityInfoData);
        when(persistenceManager.updateEntity(entityInfoData)).thenThrow(new TransactionRequiredException());

        entityPersistenceHandler.updateEntity(entityInfo);

    }

    @Test(expected = CoreEntityServiceException.class)
    public void testUpdateEntityPersistenceException() {

        when(entityMapper.fromAPIToModel(entityInfo, OperationType.UPDATE)).thenReturn(entityInfoData);
        when(persistenceManager.updateEntity(entityInfoData)).thenThrow(new PersistenceException());

        entityPersistenceHandler.updateEntity(entityInfo);

    }

    @Test(expected = CoreEntityServiceException.class)
    public void testUpdateEntityRunTimeException() {

        when(entityMapper.fromAPIToModel(entityInfo, OperationType.UPDATE)).thenReturn(entityInfoData);
        when(persistenceManager.updateEntity(entityInfoData)).thenThrow(new TransactionRequiredException());

        entityPersistenceHandler.updateEntity(entityInfo);

    }

    /*
     * @Test(expected = CoreEntityServiceException.class) public void testUpdateCertificateStatus_EntityServiceException() { final Set<CertificateData> certificateDatasSet = new
     * HashSet<CertificateData>(); CertificateData certificateData = new CertificateData(); certificateData.setStatus(CertificateStatus.ACTIVE); certificateDatasSet.add(certificateData);
     * entityInfoData.setCertificateDatas(certificateDatasSet); entityInfoData.setStatus(EntityStatus.ACTIVE);
     * 
     * // when(persistenceManager.updateEntity(certificateData)).thenThrow(new TransactionRequiredException());
     * 
     * entityPersistenceHandler.updateCertificateStatus(entityInfoData, EntityStatus.INACTIVE); }
     */

    @Test
    public void testUpdateCertificateStatus_Active() {

        final Set<CertificateData> certificateDatasSet = new HashSet<CertificateData>();
        CertificateData certificateData = new CertificateData();
        certificateData.setStatus(CertificateStatus.INACTIVE);
        certificateData.setNotAfter(new Date());
        certificateDatasSet.add(certificateData);
        entityInfoData.setCertificateDatas(certificateDatasSet);
        entityInfoData.setStatus(EntityStatus.INACTIVE);

        // when(persistenceManager.updateEntity(certificateData)).thenReturn(null);

        entityPersistenceHandler.updateCertificateStatus(entityInfoData, EntityStatus.ACTIVE);
    }

    @Test
    public void testUpdateCertificateStatus_Inactive() {
        final Set<CertificateData> certificateDatasSet = new HashSet<CertificateData>();
        CertificateData certificateData = new CertificateData();
        certificateData.setStatus(CertificateStatus.ACTIVE);
        certificateDatasSet.add(certificateData);
        entityInfoData.setCertificateDatas(certificateDatasSet);
        entityInfoData.setStatus(EntityStatus.ACTIVE);

        // when(persistenceManager.updateEntity(certificateData)).thenReturn(null);

        entityPersistenceHandler.updateCertificateStatus(entityInfoData, EntityStatus.INACTIVE);
    }

    @Test
    public void testUpdateCertificateStatus() {
        final Set<CertificateData> certificateDatasSet = new HashSet<CertificateData>();
        CertificateData certificateData = new CertificateData();
        certificateDatasSet.add(certificateData);
        entityInfoData.setCertificateDatas(certificateDatasSet);

        entityPersistenceHandler.updateCertificateStatus(entityInfoData, EntityStatus.ACTIVE);
    }

    @Test(expected = CoreEntityServiceException.class)
    public void testdeleteEntity() {
        entityInfoData.setStatus(EntityStatus.NEW);
        when(entityMapper.fromAPIToModel(entityInfo, OperationType.DELETE)).thenReturn(entityInfoData);
        Mockito.doThrow(new TransactionRequiredException()).when(persistenceManager).deleteEntity(entityInfoData);
        entityPersistenceHandler.deleteEntity(entityInfoData);

    }

    @Test(expected = CoreEntityServiceException.class)
    public void testdeleteEntity_PersistenceException() {
        entityInfoData.setStatus(EntityStatus.NEW);
        when(entityMapper.fromAPIToModel(entityInfo, OperationType.DELETE)).thenReturn(entityInfoData);
        Mockito.doThrow(new PersistenceException()).when(persistenceManager).deleteEntity(entityInfoData);
        entityPersistenceHandler.deleteEntity(entityInfoData);

    }

}
