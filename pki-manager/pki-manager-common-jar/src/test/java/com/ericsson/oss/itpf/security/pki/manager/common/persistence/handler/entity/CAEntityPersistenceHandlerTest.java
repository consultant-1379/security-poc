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
package com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.persistence.EntityExistsException;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceException;
import javax.persistence.Query;
import javax.persistence.TransactionRequiredException;
import javax.xml.datatype.DatatypeFactory;

import org.junit.Assert;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.data.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.exception.EntityStatusUpdateFailedException;
import com.ericsson.oss.itpf.security.pki.manager.common.helpers.DefaultCertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.ModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.CAEntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.EntitiesModelMapperFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entityv1.EntitiesModelMapperFactoryv1;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.ModelMapperv1;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.CAEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.NotificationSeverity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entities;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.filter.EntitiesFilter;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateExpiryNotificationDetailsData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.TrustProfileData;


@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class CAEntityPersistenceHandlerTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(AbstractEntityPersistenceHandler.class);

    @InjectMocks
    CAEntityPersistenceHandler<AbstractEntity> caEntityPersistenceHandler;

    @Mock
    EntitiesModelMapperFactory entityModelMapperFactory;

    @Mock
    EntitiesModelMapperFactoryv1 entityModelMapperFactoryv1;

    @Mock
    ModelMapper modelMapper;

    @Mock
    ModelMapperv1 modelMapperv1;

    @Mock
    CAEntityMapper caEntityMapper;

    @Mock
    EntityManager entityManager;

    @Mock
    Query query;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    DefaultCertificateExpiryNotificationDetails defaultCertExpiryNotificationDetails;

    CAEntity caEntity;
    Entity entity = new Entity();
    CAEntityData caEntityData;

    List<CAEntityData> caEntityDataList;
    List<CAEntity> caEntityList;
    Map<String, Object> entityInputs;
    CertificateAuthority certificateAuthority;

    List<CertificateProfileData> certificateProfileDatas = new ArrayList<CertificateProfileData>();
    CertificateExpiryNotificationDetails certificateExpiryNotificationDetails = new CertificateExpiryNotificationDetails();
    Set<CertificateExpiryNotificationDetails> certificateExpiryNotificationDetailsSet = new HashSet<CertificateExpiryNotificationDetails>();

    long id;
    String name;

    private final static String trustProfileQuery = "select t from TrustProfileData t join t.internalCAs c where t.active in(:is_active) and c.id=:internalca_id";
    private final static String queryForFetchActiveCAEntities = "select id,name from caentity where status_id= :status_id";

    @Before
    public void setUp() throws Exception {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();

        caEntityDataList = entitiesSetUpData.getCaEntityDataList();
        caEntityList = entitiesSetUpData.getCaEntityList();

        caEntity = caEntityList.get(0);
        caEntityData = caEntityDataList.get(0);

        id = caEntity.getCertificateAuthority().getId();
        name = caEntity.getCertificateAuthority().getName();
        certificateAuthority = caEntity.getCertificateAuthority();
        certificateExpiryNotificationDetails.setNotificationSeverity(NotificationSeverity.CRITICAL);
        certificateExpiryNotificationDetails.setPeriodBeforeExpiry(DatatypeFactory.newInstance().newDuration("P30D"));
        certificateExpiryNotificationDetails.setFrequencyOfNotification(DatatypeFactory.newInstance().newDuration("P1D"));
        certificateExpiryNotificationDetailsSet.add(certificateExpiryNotificationDetails);

        certificateProfileDatas.addAll(entitiesSetUpData.getCertificateProfileDatas());

        entityInputs = entitiesSetUpData.getInput();

        when(entityModelMapperFactory.getEntitiesMapper(EntityType.CA_ENTITY)).thenReturn(modelMapper);

        when(entityModelMapperFactoryv1.getEntitiesMapper(EntityType.CA_ENTITY)).thenReturn(modelMapperv1);

        when(modelMapper.fromAPIToModel(caEntity)).thenReturn(caEntityData);

        when(persistenceManager.findEntityByName(CAEntityData.class, name, EntitiesSetUpData.CA_NAME_PATH)).thenReturn(caEntityData);

        when(modelMapper.toAPIFromModel(caEntityData)).thenReturn(caEntity);

        when(modelMapperv1.toApi(caEntityData, MappingDepth.LEVEL_0)).thenReturn(caEntity);

        when(modelMapperv1.toApi(caEntityData, MappingDepth.LEVEL_1)).thenReturn(caEntity);

        when(persistenceManager.findEntityByIdAndName(CAEntityData.class, id, name, EntitiesSetUpData.CA_NAME_PATH)).thenReturn(caEntityData);

        Mockito.when(defaultCertExpiryNotificationDetails.prepareDefaultCertificateExpiryNotificationDetails()).thenReturn(certificateExpiryNotificationDetailsSet);
    }

    @Test
    public void testCreateEntity() {

        assertEquals(caEntity, caEntityPersistenceHandler.createEntity(caEntity));

    }

    @Test(expected = EntityServiceException.class)
    public void testCreateEntityPersistenceException() {

        when(persistenceManager.findEntityByName(CAEntityData.class, name, EntitiesSetUpData.CA_NAME_PATH)).thenThrow(new PersistenceException());

        caEntityPersistenceHandler.createEntity(caEntity);

    }

    @Test(expected = EntityAlreadyExistsException.class)
    public void testCreateEntityExistsException() {

        Mockito.doThrow(new EntityExistsException()).when(persistenceManager).createEntity(caEntityData);

        caEntityPersistenceHandler.createEntity(caEntity);

    }

    @Test(expected = EntityServiceException.class)
    public void testCreateTransactionRequiredException() {

        Mockito.doThrow(new TransactionRequiredException()).when(persistenceManager).createEntity(caEntityData);

        caEntityPersistenceHandler.createEntity(caEntity);

    }

    @Test(expected = NullPointerException.class)
    public void testCreateEntityNull() {

        caEntityPersistenceHandler.createEntity(null);

    }

    @Test(expected = NullPointerException.class)
    public void testCreateEntityEmpty() {

        caEntityPersistenceHandler.createEntity(new CAEntity());

    }

    @Test(expected = ClassCastException.class)
    public void testCreateEntityWrongType() {

        caEntityPersistenceHandler.createEntity(entity);

    }

    @Test
    public void testUpdateEntity() {

        when(persistenceManager.updateEntity(caEntityData)).thenReturn(caEntityData);
        when(persistenceManager.findEntity(CAEntityData.class, id)).thenReturn(caEntityData);
        when(entityModelMapperFactoryv1.getEntitiesMapper(EntityType.CA_ENTITY)).thenReturn(modelMapperv1);

        assertEquals(caEntity, caEntityPersistenceHandler.updateEntity(caEntity));

    }

    @Test(expected = EntityNotFoundException.class)
    public void testUpdateEntityTransactionRequiredException() {

        when(persistenceManager.updateEntity(caEntityData)).thenThrow(new TransactionRequiredException());

        caEntityPersistenceHandler.updateEntity(caEntity);

    }

    @Test(expected = EntityNotFoundException.class)
    public void testUpdateEntityRunTimeException() {

        when(persistenceManager.updateEntity(caEntityData)).thenThrow(new CAEntityException());

        caEntityPersistenceHandler.updateEntity(caEntity);

    }

    @Test(expected = NullPointerException.class)
    public void testUpdateEntityNull() {

        caEntityPersistenceHandler.updateEntity(null);

    }

    @Test
    public void testGetEntity() {

        assertEquals(caEntity, caEntityPersistenceHandler.getEntity(caEntity));

    }

    @Test(expected = ClassCastException.class)
    public void testGetEntityWrongType() {

        caEntityPersistenceHandler.getEntity(entity);

    }

    @Test(expected = NullPointerException.class)
    public void testGetEntityEmpty() {

        caEntityPersistenceHandler.getEntity(new CAEntity());

    }

    @Test(expected = InvalidEntityAttributeException.class)
    public void testGetEntityNull() {

        caEntity.getCertificateAuthority().setId(0);
        caEntity.getCertificateAuthority().setName(null);

        caEntityPersistenceHandler.getEntity(caEntity);

    }

    @Test(expected = EntityServiceException.class)
    public void testGetEntityPersistenceException() {

        when(persistenceManager.findEntityByIdAndName(CAEntityData.class, id, name, EntitiesSetUpData.CA_NAME_PATH)).thenThrow(new PersistenceException());

        caEntityPersistenceHandler.getEntity(caEntity);

    }

    @Test(expected = EntityServiceException.class)
    public void testGetEntityException() {

        when(persistenceManager.findEntityByIdAndName(CAEntityData.class, id, name, EntitiesSetUpData.CA_NAME_PATH)).thenThrow(new EntityServiceException());

        caEntityPersistenceHandler.getEntity(caEntity);

    }

    @Test(expected = EntityNotFoundException.class)
    public void testGetEntityEntityNotFound() {

        when(persistenceManager.findEntityByIdAndName(CAEntityData.class, id, name, EntitiesSetUpData.CA_NAME_PATH)).thenReturn(null);

        caEntityPersistenceHandler.getEntity(caEntity);

    }

    @Test
    public void testGetEntityById() {

        caEntity.getCertificateAuthority().setName(null);

        when(persistenceManager.findEntity(CAEntityData.class, id)).thenReturn(caEntityData);

        assertEquals(caEntityPersistenceHandler.getEntity(caEntity), caEntity);

    }

    @Test(expected = EntityServiceException.class)
    public void testGetEntityByIdPersistenceException() {

        caEntity.getCertificateAuthority().setName(null);

        when(persistenceManager.findEntity(CAEntityData.class, id)).thenThrow(new PersistenceException());

        caEntityPersistenceHandler.getEntity(caEntity);

    }

    @Test(expected = EntityServiceException.class)
    public void testGetEntityByIdException() {

        caEntity.getCertificateAuthority().setName(null);

        when(persistenceManager.findEntity(CAEntityData.class, id)).thenThrow(new EntityServiceException());

        caEntityPersistenceHandler.getEntity(caEntity);

    }

    @Test(expected = EntityNotFoundException.class)
    public void testGetEntityByIdEntityNotFound() {

        caEntity.getCertificateAuthority().setName(null);

        when(persistenceManager.findEntity(CAEntityData.class, id)).thenReturn(null);

        caEntityPersistenceHandler.getEntity(caEntity);

    }

    @Test
    public void testGetEntityByName() {

        caEntity.getCertificateAuthority().setId(0);

        assertEquals(caEntityPersistenceHandler.getEntity(caEntity), caEntity);

    }

    @Test(expected = EntityServiceException.class)
    public void testGetEntityByNamePersistenceException() {

        caEntity.getCertificateAuthority().setId(0);

        when(persistenceManager.findEntityByName(CAEntityData.class, name, EntitiesSetUpData.CA_NAME_PATH)).thenThrow(new PersistenceException());

        caEntityPersistenceHandler.getEntity(caEntity);

    }

    @Test(expected = EntityServiceException.class)
    public void testGetEntityByNameException() {

        caEntity.getCertificateAuthority().setId(0);

        when(persistenceManager.findEntityByName(CAEntityData.class, name, EntitiesSetUpData.CA_NAME_PATH)).thenThrow(new EntityServiceException());

        caEntityPersistenceHandler.getEntity(caEntity);

    }

    @Test(expected = EntityNotFoundException.class)
    public void testGetEntityByNameEntityNotFound() {

        caEntity.getCertificateAuthority().setId(0);

        when(persistenceManager.findEntityByName(CAEntityData.class, name, EntitiesSetUpData.CA_NAME_PATH)).thenReturn(null);

        caEntityPersistenceHandler.getEntity(caEntity);

    }

    @Test
    public void testGetEntities() {

        final Entities entities = new Entities();
        final List<Object> caEntityListExpected = new ArrayList<Object>();

        caEntityListExpected.add(caEntity);
        entities.setCAEntities(caEntityList);

        when(persistenceManager.getAllEntityItems(CAEntityData.class)).thenReturn(caEntityDataList);

        when(modelMapper.toAPIModelList(caEntityDataList)).thenReturn(caEntityListExpected);

        when(modelMapperv1.toApi(caEntityDataList, MappingDepth.LEVEL_1)).thenReturn(caEntityListExpected);

        assertEquals(entities, caEntityPersistenceHandler.getEntities(EntityType.CA_ENTITY));

    }

    @Test(expected = EntityServiceException.class)
    public void testGetEntitiesPersistenceException() {

        when(persistenceManager.getAllEntityItems(CAEntityData.class)).thenThrow(new PersistenceException());

        caEntityPersistenceHandler.getEntities(EntityType.CA_ENTITY);

    }

    @Test(expected = EntityServiceException.class)
    public void testGetEntitiesException() {

        when(persistenceManager.getAllEntityItems(CAEntityData.class)).thenThrow(new EntityServiceException());

        caEntityPersistenceHandler.getEntities(EntityType.CA_ENTITY);

    }

    @Test
    public void testDeleteEntity() {

        caEntityPersistenceHandler.deleteEntity(caEntity);

        verify(persistenceManager).deleteEntity(caEntityData);

    }

    @Test(expected = EntityServiceException.class)
    public void testDeleteEntityPersistException() {

        Mockito.doThrow(new PersistenceException()).when(persistenceManager).deleteEntity(caEntityData);

        caEntityPersistenceHandler.deleteEntity(caEntity);

        verify(persistenceManager).deleteEntity(caEntityData);

    }

    @Test(expected = EntityServiceException.class)
    public void testDeleteEntityTransactionRequiredException() {

        Mockito.doThrow(new TransactionRequiredException()).when(persistenceManager).deleteEntity(caEntityData);

        caEntityPersistenceHandler.deleteEntity(caEntity);

        verify(persistenceManager).deleteEntity(caEntityData);

    }

    @Test(expected = EntityServiceException.class)
    public void testDeleteEntityException_Service() {

        Mockito.doThrow(new PersistenceException()).when(persistenceManager).deleteEntity(caEntityData);

        caEntityPersistenceHandler.deleteEntity(caEntity);

        verify(persistenceManager).deleteEntity(caEntityData);

    }

    @Test
    public void testDeleteEntityInActive() {

        caEntityData.getCertificateAuthorityData().setStatus(CAStatus.INACTIVE.getId());

        when(persistenceManager.findEntityByIdAndName(CAEntityData.class, id, name, EntitiesSetUpData.CA_NAME_PATH)).thenReturn(caEntityData);

        caEntityPersistenceHandler.deleteEntity(caEntity);

        verify(persistenceManager).updateEntity(caEntityData);

    }

    @Test
    public void testDeleteEntityWithInActive() {

        caEntity.getCertificateAuthority().setStatus(CAStatus.INACTIVE);
        when(persistenceManager.findEntityByIdAndName(CAEntityData.class, id, name, EntitiesSetUpData.CA_NAME_PATH)).thenReturn(caEntityData);

        caEntityPersistenceHandler.deleteEntity(caEntity);

        verify(persistenceManager).deleteEntity(caEntityData);

    }

    @Test(expected = EntityInUseException.class)
    public void testIsDeletableEntityActive() {

        caEntityData.getCertificateAuthorityData().setStatus(CAStatus.ACTIVE.getId());

        when(persistenceManager.findEntityByIdAndName(CAEntityData.class, id, name, EntitiesSetUpData.CA_NAME_PATH)).thenReturn(caEntityData);

        caEntityPersistenceHandler.isDeletable(caEntity);

    }

    @Test(expected = EntityServiceException.class)
    public void testIsDeletableEntityActive_PersistException() {

        final Map<String, Object> input = new HashMap<String, Object>();
        input.put("issuerData", caEntityData);
        input.put("active", true);

        caEntityData.getCertificateAuthorityData().setStatus(CAStatus.ACTIVE.getId());

        Mockito.doThrow(new PersistenceException()).when(persistenceManager).findEntitiesWhere(CertificateProfileData.class, input);

        when(persistenceManager.findEntityByIdAndName(CAEntityData.class, id, name, EntitiesSetUpData.CA_NAME_PATH)).thenReturn(caEntityData);

        caEntityPersistenceHandler.isDeletable(caEntity);

    }

    @Test(expected = EntityInUseException.class)
    public void testIsDeletableEntityWithCertificateProfile() {

        final Map<String, Object> input = new HashMap<String, Object>();
        input.put("issuerData", caEntityData);
        input.put("active", true);
        when(persistenceManager.findEntitiesWhere(CertificateProfileData.class, input)).thenReturn(certificateProfileDatas);
        when(persistenceManager.findEntityByIdAndName(CAEntityData.class, id, name, EntitiesSetUpData.CA_NAME_PATH)).thenReturn(caEntityData);

        caEntityPersistenceHandler.isDeletable(caEntity);

    }

    @Test
    public void testIsDeletableEntityWithTrustProfile() {

        final TrustProfileData trustProfileData = new TrustProfileData();
        final List<Object> trustProfileDatas = new ArrayList<Object>();

        trustProfileData.setId(1);
        trustProfileDatas.add(trustProfileData);
        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("internalca_id", caEntityData.getId());
        attributes.put("is_active", true);
        when(persistenceManager.findEntitiesByAttributes(trustProfileQuery, attributes)).thenReturn(trustProfileDatas);

        when(persistenceManager.findEntityByIdAndName(CAEntityData.class, id, name, EntitiesSetUpData.CA_NAME_PATH)).thenReturn(caEntityData);

        Assert.assertTrue(caEntityPersistenceHandler.isDeletable(caEntity));
    }

    @Test(expected = EntityInUseException.class)
    public void testIsDeletableEntityWithCertificate() {

        final CertificateData certificateData = new CertificateData();
        certificateData.setId(1);
        certificateData.setStatus(CertificateStatus.ACTIVE.getId());

        final Set<CertificateData> certificateDatas = new HashSet<CertificateData>();
        certificateDatas.add(certificateData);

        caEntityData.getCertificateAuthorityData().setCertificateDatas(certificateDatas);
        caEntityData.getCertificateAuthorityData().setStatus(CAStatus.ACTIVE.getId());

        when(persistenceManager.findEntityByIdAndName(CAEntityData.class, id, name, EntitiesSetUpData.CA_NAME_PATH)).thenReturn(caEntityData);

        caEntityPersistenceHandler.isDeletable(caEntity);

    }

    @Test(expected = EntityServiceException.class)
    public void testIsDeletableEntity_EntityServiceException() {

        when(persistenceManager.findEntityByIdAndName(CAEntityData.class, id, name, EntitiesSetUpData.CA_NAME_PATH)).thenThrow(new EntityServiceException("Invalid Id or Name "));

        caEntityPersistenceHandler.isDeletable(caEntity);

    }

    @Test(expected = EntityNotFoundException.class)
    public void testIsDeletableEntity_EntityNotFoundException() {

        when(persistenceManager.findEntityByIdAndName(CAEntityData.class, id, name, EntitiesSetUpData.CA_NAME_PATH)).thenReturn(null);

        caEntityPersistenceHandler.isDeletable(caEntity);

    }

    @Test
    public void testIsNameAvailableFalse() {

        assertFalse(caEntityPersistenceHandler.isNameAvailable(name));

    }

    @Test
    public void testNameAvailableTrue() {

        when(persistenceManager.findEntityByName(CAEntityData.class, name, EntitiesSetUpData.CA_NAME_PATH)).thenReturn(null);

        assertTrue(caEntityPersistenceHandler.isNameAvailable(name));

    }

    @Test(expected = EntityServiceException.class)
    public void testNameAvailableException() {

        when(persistenceManager.findEntityByName(CAEntityData.class, name, EntitiesSetUpData.CA_NAME_PATH)).thenThrow(new PersistenceException());

        assertTrue(caEntityPersistenceHandler.isNameAvailable(name));

    }

    @Test
    public void testGetEntityWhere() {

        when(persistenceManager.findEntityWhere(CAEntityData.class, entityInputs)).thenReturn(caEntityData);

        caEntityPersistenceHandler.getEntityWhere(CAEntityData.class, entityInputs);

        verify(persistenceManager).findEntityWhere(CAEntityData.class, entityInputs);

    }

    @Test(expected = EntityServiceException.class)
    public void testGetEntityWhereException() {

        when(persistenceManager.findEntityWhere(CAEntityData.class, entityInputs)).thenThrow(new PersistenceException());

        caEntityPersistenceHandler.getEntityWhere(CAEntityData.class, entityInputs);

    }

    @Test
    public void testGetEntitiesByStatusWithEmptyList() {
        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("certificateAuthorityData.status", 2);
        when(persistenceManager.findEntitiesWhere(CAEntityData.class, attributes)).thenReturn(null);
        caEntityPersistenceHandler.getEntitiesByStatus(1);
        assertSame(null, caEntityPersistenceHandler.getEntitiesByStatus(1));
    }

    @Test
    public void testGetEntitiesByStatus() {

        final List<Object> caEntityListExpected = new ArrayList<Object>();
        caEntityListExpected.add(caEntity);

        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("certificateAuthorityData.status", 2);
        when(persistenceManager.findEntitiesWhere(CAEntityData.class, attributes)).thenReturn(caEntityDataList);
        when(modelMapper.toAPIModelList(caEntityDataList)).thenReturn(caEntityListExpected);

        assertEquals(caEntityList, caEntityPersistenceHandler.getEntitiesByStatus(2));

    }

    @Test
    public void testGetEntitiesCountByFilter() {

        final EntitiesFilter entitiesFilter = getEntitiesFilter();
        caEntityPersistenceHandler.getEntitiesCountByFilter(entitiesFilter);
        entitiesFilter.getType().remove(EntityType.CA_ENTITY);
        caEntityPersistenceHandler.getEntitiesCountByFilter(entitiesFilter);

    }

    @Test(expected = EntityServiceException.class)
    public void testGetEntitiesCountByFilterPersistException() {

        final EntitiesFilter entitiesFilter = getEntitiesFilter();
        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("externalCA", false);
        Mockito.doThrow(new PersistenceException()).when(persistenceManager).findEntitiesCountByAttributes(Mockito.anyString(), Mockito.anyMap());
        caEntityPersistenceHandler.getEntitiesCountByFilter(entitiesFilter);
    }

    private EntitiesFilter getEntitiesFilter() {
        final EntitiesFilter entitiesFilter = new EntitiesFilter();

        entitiesFilter.setName("");
        entitiesFilter.setCertificateAssigned(1);

        final List<EntityStatus> status = new ArrayList<EntityStatus>();
        status.add(EntityStatus.ACTIVE);
        entitiesFilter.setStatus(status);
        final List<EntityType> type = new ArrayList<EntityType>();
        type.add(EntityType.CA_ENTITY);
        entitiesFilter.setType(type);
        return entitiesFilter;
    }

    @Test
    public void testupdateCAEntityStatusToInactive() {

        when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        when(entityManager.createNativeQuery(Mockito.anyString())).thenReturn(query);
        when(query.executeUpdate()).thenReturn(1);

        caEntityPersistenceHandler.updateCAEntityStatusToInactive();

    }

    @Test(expected = EntityStatusUpdateFailedException.class)
    public void testUpdateCAEntityStatusToInactive_PersistException() {

        when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        when(entityManager.createNativeQuery(Mockito.anyString())).thenReturn(query);
        Mockito.doThrow(new PersistenceException()).when(query).executeUpdate();

        caEntityPersistenceHandler.updateCAEntityStatusToInactive();
    }

    @Test
    public void testFetchCAEntitiesIdAndNameByStatus() {

        final List<Object[]> entities = new ArrayList<Object[]>();

        Object[] e = new Object[2];
        final BigInteger bigInt = new BigInteger("2");

        e[0] = bigInt;
        e[1] = "entityName";

        entities.add(e);

        final List<CAEntity> expected = new ArrayList<CAEntity>();
        final CAEntity caEntity = new CAEntity();
        final CertificateAuthority certificateAuthority = new CertificateAuthority();

        certificateAuthority.setId(((BigInteger) e[0]).longValue());
        certificateAuthority.setName((String) e[1]);

        caEntity.setCertificateAuthority(certificateAuthority);
        expected.add(caEntity);

        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("status_id", CAStatus.ACTIVE.getId());

        when(persistenceManager.findEntitiesByNativeQuery(Mockito.anyString(), Mockito.anyMap())).thenReturn(entities);

        final List<CAEntity> entities2 = caEntityPersistenceHandler.fetchCAEntitiesIdAndNameByStatus(CAStatus.ACTIVE, true);
        Assert.assertEquals(expected, entities2);
    }

    /**
     * Method to test fetchCAEntitiesIdAndNameByStatus in negative scenario
     */
    @Test(expected = EntityServiceException.class)
    public void testFetchCAEntitiesIdAndNameByStatus_EntityServiceException() {

        final List<Object[]> entities = new ArrayList<Object[]>();

        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("status_id", CAStatus.ACTIVE.getId());

        when(persistenceManager.findEntitiesByNativeQuery(queryForFetchActiveCAEntities, attributes)).thenThrow(new PersistenceException());

        final List<CAEntity> entities2 = caEntityPersistenceHandler.fetchCAEntitiesIdAndNameByStatus(CAStatus.ACTIVE, true);
        Assert.assertEquals(entities, entities2);

    }

    @Test
    public void testGetEntityForCertificateGeneration() {
        when(caEntityMapper.toAPIFromModelWithoutCertificates(caEntityData)).thenReturn(caEntity);
        assertNotNull(caEntityPersistenceHandler.getEntityForCertificateGeneration(caEntity));
    }

    @Test
    public void testPersistEntityData() {
        caEntityPersistenceHandler.persistEntityData(caEntityData);
        Mockito.verify(persistenceManager).createEntity(caEntityData);
    }

    @Test(expected = EntityAlreadyExistsException.class)
    public void testPersistEntityData_EntityAlreadyExistsException() {

        Mockito.doThrow(new EntityExistsException()).when(persistenceManager).createEntity(caEntityData);
        caEntityPersistenceHandler.persistEntityData(caEntityData);
    }

    @Test(expected = EntityServiceException.class)
    public void testPersistEntityData_TransactionRequiredException() {

        Mockito.doThrow(new TransactionRequiredException()).when(persistenceManager).createEntity(caEntityData);
        caEntityPersistenceHandler.persistEntityData(caEntityData);
    }

    @Test
    public void testMergeCertificateExpiryNotificationDetails() {

        final Set<CertificateExpiryNotificationDetailsData> updateCertExpiryNotificationDetails = new HashSet<CertificateExpiryNotificationDetailsData>();

        final String qlString = "select c from CertificateExpiryNotificationDetailsData c where c.id in(select cendd.id from CAEntityData ced inner join ced.certificateExpiryNotificationDetailsData cendd  WHERE ced.certificateAuthorityData.name = :name and cendd.notificationSeverity= :severity  and ced.externalCA = false) ORDER BY c.id DESC ";
        final CAEntityData caEntityData = new CAEntityData();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();

        final CertificateExpiryNotificationDetailsData cert = new CertificateExpiryNotificationDetailsData();

        updateCertExpiryNotificationDetails.add(cert);

        caEntityData.setCertificateExpiryNotificationDetailsData(updateCertExpiryNotificationDetails);
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);

        when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        when(entityManager.createQuery(qlString)).thenReturn(query);
        when(query.getSingleResult()).thenReturn(cert);

        caEntityPersistenceHandler.mergeCertificateExpiryNotificationDetails(caEntityData);
    }
}
