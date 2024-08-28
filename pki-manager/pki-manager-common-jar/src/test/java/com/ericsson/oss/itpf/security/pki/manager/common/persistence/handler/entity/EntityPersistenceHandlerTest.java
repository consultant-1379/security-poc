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
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertSame;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.doReturn;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.naming.InvalidNameException;
import javax.persistence.EntityExistsException;
import javax.persistence.EntityManager;
import javax.persistence.PersistenceException;
import javax.persistence.Query;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.EntityStatus;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.manager.common.data.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.data.EntityCategorySetUpData;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.ModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.EntitiesModelMapperFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.EntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entityv1.EntitiesModelMapperFactoryv1;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entityv1.EntityModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.MappingDepth;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1.ModelMapperv1;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.SubjectUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyDeletedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.SerialNumberNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entities;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.filter.EntitiesFilter;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateExpiryNotificationDetailsData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityCategoryData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityInfoData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.SubjectIdentificationData;

@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class EntityPersistenceHandlerTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(AbstractEntityPersistenceHandler.class);

    @InjectMocks
    EntityPersistenceHandler entityPersistenceHandler;

    @Mock
    EntitiesModelMapperFactory entityModelMapperFactory;

    @Mock
    EntitiesModelMapperFactoryv1 entityModelMapperFactoryv1;

    @Mock
    ModelMapper modelMapper;

    @Mock
    ModelMapperv1 modelMapperv1;

    @Mock
    EntityMapper entityMapper;

    @Mock
    EntityModelMapper entityModelMapper;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    EntityManager entityManager;

    @Mock
    EntityFilterDynamicQueryBuilder entityFilterDynamicQueryBuilder;

    @Mock
    SubjectIdentificationData subjectDNHashData;

    @Mock
    CertificateExpiryNotificationDetailsData certificateExpiryNotificationDetailsData;

    @Mock
    Query query;

    private Entity entity;
    private EntityData entityData;
    private EntityCategory entityCategory;
    private EntityCategoryData entityCategoryData;
    private EntityInfoData entityInfoData;
    private CertificateData certificateData;
    private SubjectIdentificationData subjectIdentificationData;
    private CAEntity caEntity;

    List<EntityData> entityDataList;
    List<EntityData> entityDataListWithInvalidCertificate;
    List<Entity> entityList;
    Set<CertificateData> certificateDatas;
    long id;
    String name;

    private static final String ENTITY_CATEGORY_ID = "entityCategoryData";
    private static final String NAME = "name";
    private static final String ISSUER_DN = "CN=ENMSubCA";
    private static final String SUBJECT_DN = "CN=ENMSubCA";
    private static final String ENTITY_NAME = "ENMSubCA";
    private static final String SERIAL_NUMBER = "10101";
    private static final String ISSUER_NAME_OAM = "OAM";
    private static final String ISSUER_NAME_IPSEC = "IPSEC";
    private static final String ENTITY_ID = "entityId";
    private static final String SUBJECT_DN_HASH = "subjectDNHash";

    @Before
    public void setUp() {

        final EntityCategorySetUpData entityCategorySetUpData = new EntityCategorySetUpData();
        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entityCategory = entityCategorySetUpData.getEntityCategory();
        entityCategoryData = entityCategorySetUpData.getEntityCategoryData();

        caEntity = new CAEntity();

        entityDataList = entitiesSetUpData.getEntityDataList();
        entityList = entitiesSetUpData.getEntityList();
        entity = entityList.get(0);
        entityData = entityDataList.get(0);
        id = entity.getEntityInfo().getId();
        name = entity.getEntityInfo().getName();
        entityInfoData = new EntityInfoData();
        certificateDatas = new HashSet<CertificateData>();
        certificateData = new CertificateData();
        final CertificateData invalidCertificateData = new CertificateData();
        final HashSet<CertificateData> invalidCertificateDatas = new HashSet<>();
        subjectIdentificationData = new SubjectIdentificationData();

        certificateData.setSubjectDN(SUBJECT_DN);
        certificateData.setSerialNumber(SERIAL_NUMBER);
        certificateData.setStatus(1);
        certificateDatas.add(certificateData);

        invalidCertificateData.setSubjectDN(SUBJECT_DN);
        invalidCertificateData.setSerialNumber(SERIAL_NUMBER);
        invalidCertificateData.setStatus(1);
        invalidCertificateDatas.add(invalidCertificateData);
        entityDataListWithInvalidCertificate = entitiesSetUpData.getEntityDataList();
        final CAEntityData issuerData = new CAEntityData();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateData.setNotAfter(new Date(19, 10, 28, 12, 30, 4));
        certificateAuthorityData.setCertificateDatas(certificateDatas);
        issuerData.setCertificateAuthorityData(certificateAuthorityData);

        for (final EntityData entityData : entityDataListWithInvalidCertificate) {
            entityData.getEntityProfileData().getCertificateProfileData().setIssuerData(issuerData);
            for (final CertificateData certificateData : invalidCertificateDatas) {
                certificateData.setNotAfter(new Date(19, 10, 26, 12, 30, 4));
            }
            entityData.getEntityInfoData().setCertificateDatas(invalidCertificateDatas);
        }

        when(modelMapperv1.toApi(entityData, MappingDepth.LEVEL_1)).thenReturn(entity);
        when(entityModelMapperFactoryv1.getEntitiesMapper(EntityType.ENTITY)).thenReturn(modelMapperv1);
        when(entityModelMapperFactory.getEntitiesMapper(EntityType.ENTITY)).thenReturn(modelMapper);
        when(modelMapper.fromAPIToModel(entity)).thenReturn(entityData);
        when(modelMapper.toAPIFromModel(entityData)).thenReturn(entity);

        when(persistenceManager.findEntityByName(EntityData.class, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenReturn(entityData);

        when(persistenceManager.findEntityByIdAndName(EntityData.class, id, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenReturn(entityData);

    }

    @Test
    public void testCreateEntity() {

        assertEquals(entity, entityPersistenceHandler.createEntity(entity));

    }

    @Test(expected = EntityServiceException.class)
    public void testCreateEntityPersistenceException() {

        when(persistenceManager.findEntityByName(EntityData.class, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenThrow(new PersistenceException());

        entityPersistenceHandler.createEntity(entity);

    }

    @Test(expected = EntityServiceException.class)
    public void testCreateEntityMappingException() {

        when(modelMapper.fromAPIToModel(entity)).thenThrow(new EntityServiceException());

        entityPersistenceHandler.createEntity(entity);

    }

    @Test(expected = EntityAlreadyExistsException.class)
    public void testCreateEntityExistsException() {

        Mockito.doThrow(new EntityExistsException()).when(persistenceManager).createEntity(entityData);

        entityPersistenceHandler.createEntity(entity);

    }

    @Test(expected = EntityServiceException.class)
    public void testCreateTransactionRequiredException() {

        Mockito.doThrow(new EntityServiceException()).when(persistenceManager).createEntity(entityData);

        entityPersistenceHandler.createEntity(entity);

    }

    @Test(expected = NullPointerException.class)
    public void testCreateEntityNull() {

        entityPersistenceHandler.createEntity(null);

    }

    @Test(expected = NullPointerException.class)
    public void testCreateEntityEmpty() {

        entityPersistenceHandler.createEntity(new Entity());

    }

    @Test(expected = ClassCastException.class)
    public void testCreateEntityWrongType() {

        entityPersistenceHandler.createEntity(caEntity);

    }

    @Test
    public void testUpdateEntity() {
        when(persistenceManager.updateEntity(entityData)).thenReturn(entityData);
        when(persistenceManager.findEntity(EntityData.class, id)).thenReturn(entityData);
        final Map<String, Object> input = new HashMap<String, Object>();
        input.put(ENTITY_ID, id);
        Mockito.when(persistenceManager.findEntityWhere(SubjectIdentificationData.class, input)).thenReturn(subjectDNHashData);
        assertEquals(entity, entityPersistenceHandler.updateEntity(entity));

    }

    @Test(expected = EntityNotFoundException.class)
    public void testUpdateEntityTransactionRequiredException() {

        when(persistenceManager.updateEntity(entityData)).thenThrow(new EntityNotFoundException());

        entityPersistenceHandler.updateEntity(entity);

    }

    @Test(expected = EntityNotFoundException.class)
    public void testUpdateEntityRunTimeException() {

        when(persistenceManager.updateEntity(entityData)).thenThrow(new EntityServiceException());

        entityPersistenceHandler.updateEntity(entity);

    }

    @Test(expected = NullPointerException.class)
    public void testUpdateEntityNull() {

        entityPersistenceHandler.updateEntity(null);

    }

    @Test
    public void testGetEntityForCertificateGeneration() {

        when(entityModelMapper.toApi(entityData, MappingDepth.LEVEL_1)).thenReturn(entity);
        assertEquals(entity, entityPersistenceHandler.getEntityForCertificateGeneration(entity));
    }

    @Test(expected = ClassCastException.class)
    public void testGetEntityWrongType() {

        entityPersistenceHandler.getEntity(caEntity);

    }

    @Test(expected = NullPointerException.class)
    public void testGetEntityEmpty() {

        entityPersistenceHandler.getEntity(new Entity());

    }

    @Test(expected = InvalidEntityAttributeException.class)
    public void testGetEntityNull() {

        entity.getEntityInfo().setId(0);
        entity.getEntityInfo().setName(null);

        entityPersistenceHandler.getEntity(entity);

    }

    @Test(expected = EntityServiceException.class)
    public void testGetEntityPersistenceException() {

        when(persistenceManager.findEntityByIdAndName(EntityData.class, id, name, EntitiesSetUpData.ENTITY_NAME_PATH))
                .thenThrow(new PersistenceException());

        entityPersistenceHandler.getEntity(entity);

    }

    @Test(expected = EntityServiceException.class)
    public void testGetEntityException() {

        when(persistenceManager.findEntityByIdAndName(EntityData.class, id, name, EntitiesSetUpData.ENTITY_NAME_PATH))
                .thenThrow(new EntityServiceException());

        entityPersistenceHandler.getEntity(entity);

    }

    @Test(expected = EntityNotFoundException.class)
    public void testGetEntityEntityNotFound() {

        when(persistenceManager.findEntityByIdAndName(EntityData.class, id, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenReturn(null);

        entityPersistenceHandler.getEntity(entity);

    }

    @Test
    public void testGetEntityById() {

        entity.getEntityInfo().setName(null);

        when(persistenceManager.findEntity(EntityData.class, id)).thenReturn(entityData);
        when(modelMapperv1.toApi(entityData, MappingDepth.LEVEL_1)).thenReturn(entity);
        assertEquals(entityPersistenceHandler.getEntity(entity), entity);

    }

    @Test(expected = EntityServiceException.class)
    public void testGetEntityByIdPersistenceException() {

        entity.getEntityInfo().setName(null);

        when(persistenceManager.findEntity(EntityData.class, id)).thenThrow(new PersistenceException());

        entityPersistenceHandler.getEntity(entity);

    }

    @Test(expected = EntityServiceException.class)
    public void testGetEntityByIdException() {

        entity.getEntityInfo().setName(null);

        when(persistenceManager.findEntity(EntityData.class, id)).thenThrow(new EntityServiceException());

        entityPersistenceHandler.getEntity(entity);

    }

    @Test(expected = EntityNotFoundException.class)
    public void testGetEntityByIdEntityNotFound() {

        entity.getEntityInfo().setName(null);

        when(persistenceManager.findEntity(EntityData.class, id)).thenReturn(null);

        entityPersistenceHandler.getEntity(entity);

    }

    @Test
    public void testGetEntityByName() {

        entity.getEntityInfo().setId(0);

        assertEquals(entityPersistenceHandler.getEntity(entity), entity);

    }

    @Test(expected = EntityServiceException.class)
    public void testGetEntityByNamePersistenceException() {

        entity.getEntityInfo().setId(0);

        when(persistenceManager.findEntityByName(EntityData.class, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenThrow(new PersistenceException());

        entityPersistenceHandler.getEntity(entity);

    }

    @Test(expected = EntityServiceException.class)
    public void testGetEntityByNameException() {

        entity.getEntityInfo().setId(0);

        when(persistenceManager.findEntityByName(EntityData.class, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenThrow(new EntityServiceException());

        entityPersistenceHandler.getEntity(entity);

    }

    @Test(expected = com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException.class)
    public void testGetEntityByNameEntityNotFound() {

        entity.getEntityInfo().setId(0);

        when(persistenceManager.findEntityByName(EntityData.class, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenReturn(null);

        entityPersistenceHandler.getEntity(entity);

    }

    @Test
    public void testGetEntities() {

        final Entities entities = new Entities();
        final List<Object> entityListExpected = new ArrayList<Object>();

        entities.setEntities(entityList);
        entityListExpected.add(entity);

        when(persistenceManager.getAllEntityItems(EntityData.class)).thenReturn(entityDataList);
        when(modelMapper.toAPIModelList(entityDataList)).thenReturn(entityListExpected);
        when(modelMapperv1.toApi(entityDataList, MappingDepth.LEVEL_1)).thenReturn(entityListExpected);
        assertEquals(entities, entityPersistenceHandler.getEntities(EntityType.ENTITY));

    }

    @Test(expected = EntityServiceException.class)
    public void testGetEntitiesPersistenceException() {

        when(persistenceManager.getAllEntityItems(EntityData.class)).thenThrow(new PersistenceException());

        entityPersistenceHandler.getEntities(EntityData.class, EntityType.ENTITY);

    }

    @Test(expected = EntityServiceException.class)
    public void testGetEntitiesException() {

        when(persistenceManager.getAllEntityItems(EntityData.class)).thenThrow(new EntityServiceException());

        entityPersistenceHandler.getEntities(EntityData.class, EntityType.ENTITY);

    }

    @Test
    public void testDeleteEntity() {

        final Map<String, Object> input = new HashMap<String, Object>();
        input.put("entityId", id);
        Mockito.when(persistenceManager.findEntityWhere(SubjectIdentificationData.class, input)).thenReturn(subjectDNHashData);

        entityPersistenceHandler.deleteEntity(entity);

        verify(persistenceManager).deleteEntity(entityData);

    }

    @Test
    public void testDeleteEntityRevoked() {

        entityData.getEntityInfoData().setStatus(EntityStatus.INACTIVE);

        when(persistenceManager.findEntityByIdAndName(EntityData.class, id, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenReturn(entityData);

        entityPersistenceHandler.deleteEntity(entity);

        verify(persistenceManager).updateEntity(entityData);

    }

    @Test
    public void testDeleteEntityReissued() {

        entityData.getEntityInfoData().setStatus(EntityStatus.REISSUE);

        when(persistenceManager.findEntityByIdAndName(EntityData.class, id, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenReturn(entityData);

        entityPersistenceHandler.deleteEntity(entity);

        verify(persistenceManager).updateEntity(entityData);

    }

    @Test(expected = EntityServiceException.class)
    public void testDeleteEntityException() {

        when(persistenceManager.findEntityByIdAndName(EntityData.class, id, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenReturn(entityData);

        Mockito.doThrow(new EntityServiceException()).when(persistenceManager).deleteEntity(entityData);

        entityPersistenceHandler.deleteEntity(entity);

    }

    @Test(expected = EntityServiceException.class)
    public void testDeleteEntityServiceException() {

        when(persistenceManager.findEntityByIdAndName(EntityData.class, id, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenReturn(entityData);

        Mockito.doThrow(new javax.persistence.PersistenceException()).when(persistenceManager).deleteEntity(entityData);

        entityPersistenceHandler.deleteEntity(entity);

    }

    @Test(expected = EntityInUseException.class)
    public void testIsDeletableEntityGenerated() {

        entityData.getEntityInfoData().setStatus(EntityStatus.ACTIVE);

        when(persistenceManager.findEntityByIdAndName(EntityData.class, id, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenReturn(entityData);

        entityPersistenceHandler.isDeletable(entity);

    }

    @Test
    public void testIsDeletableInactiveEntity() {

        entityData.getEntityInfoData().setStatus(EntityStatus.INACTIVE);

        when(persistenceManager.findEntityByIdAndName(EntityData.class, id, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenReturn(entityData);

        assertEquals(true, entityPersistenceHandler.isDeletable(entity));

    }

    @Test(expected = EntityServiceException.class)
    public void testIsDeletableReissueEntity() {

        entityData.getEntityInfoData().setStatus(EntityStatus.REISSUE);

        when(persistenceManager.findEntityByIdAndName(EntityData.class, id, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenReturn(entityData);

        entityPersistenceHandler.isDeletable(entity);

    }

    @Test(expected = EntityAlreadyDeletedException.class)
    public void testIsDeletableDeletedEntity() {

        entityData.getEntityInfoData().setStatus(EntityStatus.DELETED);

        when(persistenceManager.findEntityByIdAndName(EntityData.class, id, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenReturn(entityData);

        entityPersistenceHandler.isDeletable(entity);

    }

    @Test(expected = EntityServiceException.class)
    public void testIsDeletableEntityReissue() {

        entityData.getEntityInfoData().setStatus(EntityStatus.REISSUE);

        when(persistenceManager.findEntityByIdAndName(EntityData.class, id, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenReturn(entityData);

        entityPersistenceHandler.isDeletable(entity);

    }

    @Test
    public void testIsDeletableEntityInactive() {

        entityData.getEntityInfoData().setStatus(EntityStatus.INACTIVE);

        when(persistenceManager.findEntityByIdAndName(EntityData.class, id, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenReturn(entityData);

        entityPersistenceHandler.isDeletable(entity);

    }

    @Test(expected = EntityAlreadyDeletedException.class)
    public void testIsDeletableEntityAlreadyDeleted() {

        entityData.getEntityInfoData().setStatus(EntityStatus.DELETED);

        when(persistenceManager.findEntityByIdAndName(EntityData.class, id, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenReturn(entityData);

        entityPersistenceHandler.isDeletable(entity);

    }

    @Test(expected = EntityServiceException.class)
    public void testIsDeletableEntity_EntityServiceException() {

        when(persistenceManager.findEntityByIdAndName(EntityData.class, id, name, EntitiesSetUpData.ENTITY_NAME_PATH))
                .thenThrow(new EntityServiceException("Invalid Id or Name "));

        entityPersistenceHandler.isDeletable(entity);

    }

    @Test(expected = EntityNotFoundException.class)
    public void testIsDeletableEntity_EntityNotFoundException() {

        when(persistenceManager.findEntityByIdAndName(EntityData.class, id, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenReturn(null);

        entityPersistenceHandler.isDeletable(entity);

    }

    @Test
    public void testIsNameAvailableFalse() {

        assertFalse(entityPersistenceHandler.isNameAvailable(name));

    }

    @Test
    public void testNameAvailableTrue() {

        when(persistenceManager.findEntityByName(EntityData.class, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenReturn(null);

        assertTrue(entityPersistenceHandler.isNameAvailable(name));

    }

    @Test(expected = EntityServiceException.class)
    public void testNameAvailableException() {

        when(persistenceManager.findEntityByName(EntityData.class, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenThrow(new PersistenceException());

        assertTrue(entityPersistenceHandler.isNameAvailable(name));

    }

    /**
     * This test case is used to test the valid scenario of getOTP.
     */
    @Test
    public void testGetOTP() {
        entityPersistenceHandler.getOtp(entity);
        assertEquals(entity, entityPersistenceHandler.getEntity(entity));
    }

    /**
     * This test case is used to verify if getOTP() throws EntityServiceException when there is an internal service error.
     */
    @Test(expected = EntityServiceException.class)
    public void testInternalServiceException() {
        when(persistenceManager.findEntityByName(EntityData.class, name, EntitiesSetUpData.ENTITY_NAME_PATH)).thenThrow(new EntityServiceException());
        entityPersistenceHandler.getOtp(entity);
    }

    @Test(expected = EntityServiceException.class)
    public void testGetOTPPersistenceException() {
        when(persistenceManager.findEntityByName(EntityData.class, name, EntitiesSetUpData.ENTITY_NAME_PATH))
                .thenThrow(new javax.persistence.PersistenceException());
        entityPersistenceHandler.getOtp(entity);
    }

    /**
     * This test case is used to test valid scenario of GetEntitiesByCategory.
     */

    @Test
    public void testGetEntitiesByCategory() {

        Mockito.when(persistenceManager.findEntityByName(EntityCategoryData.class, entityCategory.getName(), NAME)).thenReturn(entityCategoryData);
        final Map<String, Object> input = new HashMap<String, Object>();
        input.put(ENTITY_CATEGORY_ID, entityCategoryData);

        Mockito.when(persistenceManager.findEntitiesWhere(EntityData.class, input)).thenReturn(entityDataList);

        final List<Object> enList = new ArrayList<Object>();

        Mockito.when(modelMapper.toAPIModelList(entityDataList)).thenReturn(enList);

        final List<Entity> entititesListByCategory = entityPersistenceHandler.getEntitiesByCategory(entityCategory, true);

        enList.addAll(entityList);
        assertNotNull(entititesListByCategory);
        for (final Object entity : enList) {
            final Entity en = (Entity) entity;
            assertEquals(en.getCategory().getName(), entityCategory.getName());
            assertEquals(en.getCategory().getId(), entityCategory.getId());

        }

    }

    /**
     * This test case is used to test negative scenario of GetEntitiesByCategory to throw EntityServiceException.
     */

    @Test(expected = EntityServiceException.class)
    public void testGetEntitiesByCategoryEx() {

        final Map<String, Object> input = new HashMap<String, Object>();
        input.put(ENTITY_CATEGORY_ID, null);

        Mockito.when(persistenceManager.findEntitiesWhere(EntityData.class, input)).thenThrow(new EntityServiceException());
        entityPersistenceHandler.getEntitiesByCategory(entityCategory, true);
    }

    @Test(expected = EntityServiceException.class)
    public void testGetEntitiesByCategoryPersistenceException() {

        final Map<String, Object> input = new HashMap<String, Object>();
        input.put(ENTITY_CATEGORY_ID, null);

        Mockito.when(persistenceManager.findEntitiesWhere(EntityData.class, input)).thenThrow(new javax.persistence.PersistenceException());
        entityPersistenceHandler.getEntitiesByCategory(entityCategory, true);
    }

    /**
     * This test case is used to test negative scenario of GetEntitiesByCategory to throw EntityNotFoundException.
     */
    @Test(expected = EntityNotFoundException.class)
    public void testGetEntitiesByCategoryEntityNotFoundEx() {

        Mockito.when(persistenceManager.findEntityByName(EntityCategoryData.class, entityCategory.getName(), NAME)).thenReturn(entityCategoryData);
        final Map<String, Object> input = new HashMap<String, Object>();
        input.put(ENTITY_CATEGORY_ID, entityCategoryData);

        Mockito.when(persistenceManager.findEntitiesWhere(EntityData.class, input)).thenReturn(null);
        entityPersistenceHandler.getEntitiesByCategory(entityCategory, true);
    }

    @Test
    public void testGetEntitiesByCategoryAndValidity() {
        final Date date = new Date();

        final EntityPersistenceHandler objA = Mockito.spy(entityPersistenceHandler);

        Mockito.when(persistenceManager.findEntityByName(EntityCategoryData.class, entityCategory.getName(), "name")).thenReturn(entityCategoryData);

        doReturn(new ArrayList<Entity>()).when(objA).getEntitiesByCategoryAndCertificateValidity(date, entityCategory);
        doReturn(new ArrayList<Entity>()).when(objA).getEntitiesByCategoryAndNotActiveCertificate(entityCategory);

        objA.getEntitiesWithInvalidCertificate(date, 100, entityCategory);
    }

    @Test
    public void testGetEntitiesWithInvalidCertificate() {
        final Date date = new Date();

        final String qlString = "select e from EntityData e where e.entityCategoryData.id in (:entityCategories)"
                + " and e.entityInfoData.status = :entityStatusInteger"
                + " and e.id not in (select ent.id from EntityData ent inner join ent.entityInfoData.certificateDatas as certificate where certificate.status= :activeStatusInInteger) ";

        Mockito.when(persistenceManager.findEntityByName(EntityCategoryData.class, entityCategory.getName(), "name")).thenReturn(entityCategoryData);
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(qlString)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(entityDataListWithInvalidCertificate);

        final String qlString2 =
                "select e from EntityData e inner join e.entityInfoData.certificateDatas as cdata where e.entityCategoryData.id in(:entityCategories)"
                        + "  and e.entityInfoData.status = :entityStatusInteger and cdata.notAfter <=  date(:validity) and cdata.status = :activeStatusInInteger";

        Mockito.when(persistenceManager.findEntityByName(EntityCategoryData.class, entityCategory.getName(), "name")).thenReturn(entityCategoryData);
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(qlString2)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(entityDataListWithInvalidCertificate);
        final List<AbstractEntity> expected = entityPersistenceHandler.getEntitiesWithInvalidCertificate(date, 100, entityCategory);

        assertEquals(expected, entityPersistenceHandler.getEntitiesWithInvalidCertificate(date, 100, entityCategory));

    }

    @Test
    public void testGetEntitiesByCategoryAndValidity1() {
        final Date date = new Date();
        final List<Entity> entityList1 = new ArrayList<Entity>();
        for (int i = 0; i < 110; i++) {
            final Entity ent = new Entity();
            final EntityInfo entityInfo = new EntityInfo();
            entityInfo.setId(i);
            ent.setEntityInfo(entityInfo);
            entityList1.add(ent);
        }

        final EntityPersistenceHandler objA = Mockito.spy(entityPersistenceHandler);

        doReturn(entityList1).when(objA).getEntitiesByCategoryAndCertificateValidity(date, entityCategory);
        doReturn(new ArrayList<Entity>()).when(objA).getEntitiesByCategoryAndNotActiveCertificate(entityCategory);
        final List<Entity> entityList = objA.getEntitiesWithInvalidCertificate(date, 100, entityCategory);
        assertTrue(entityList.size() == 100);
    }

    @Test
    public void testGetEntitiesByCategoryAndValidityWithNegativeParameter() {
        final Date date = new Date();
        final List<Entity> entityList1 = new ArrayList<Entity>();
        for (int i = 0; i < 110; i++) {
            final Entity ent = new Entity();
            final EntityInfo entityInfo = new EntityInfo();
            entityInfo.setId(i);
            ent.setEntityInfo(entityInfo);
            entityList1.add(ent);
        }

        final EntityPersistenceHandler objA = Mockito.spy(entityPersistenceHandler);

        doReturn(entityList1).when(objA).getEntitiesByCategoryAndCertificateValidity(date, entityCategory);
        doReturn(new ArrayList<Entity>()).when(objA).getEntitiesByCategoryAndNotActiveCertificate(entityCategory);
        final List<Entity> entityList = objA.getEntitiesWithInvalidCertificate(date, -5, entityCategory);
        assertTrue(entityList.size() == 110);
    }

    @Test
    public void testGetEntitiesByCategoryAndValidityWithZeroParameter() {
        final Date date = new Date();
        final List<Entity> entityList1 = new ArrayList<Entity>();
        for (int i = 0; i < 5; i++) {
            final Entity ent = new Entity();
            final EntityInfo entityInfo = new EntityInfo();
            entityInfo.setId(i);
            ent.setEntityInfo(entityInfo);
            entityList1.add(ent);
        }

        final EntityPersistenceHandler objA = Mockito.spy(entityPersistenceHandler);

        doReturn(entityList1).when(objA).getEntitiesByCategoryAndCertificateValidity(date, entityCategory);
        doReturn(new ArrayList<Entity>()).when(objA).getEntitiesByCategoryAndNotActiveCertificate(entityCategory);
        final List<Entity> entityList = objA.getEntitiesWithInvalidCertificate(date, 0, entityCategory);
        assertTrue(entityList.size() == 0);
    }

    @Test(expected = MissingMandatoryFieldException.class)
    public void testGetEntitiesByCategoryAndValidityWithWrongDate() {
        final Date date = new Date();
        final List<Entity> entityList1 = new ArrayList<Entity>();
        for (int i = 0; i < 5; i++) {
            final Entity ent = new Entity();
            final EntityInfo entityInfo = new EntityInfo();
            entityInfo.setId(i);
            ent.setEntityInfo(entityInfo);
            entityList1.add(ent);
        }

        final EntityPersistenceHandler objA = Mockito.spy(entityPersistenceHandler);
        doReturn(entityList1).when(objA).getEntitiesByCategoryAndCertificateValidity(date, entityCategory);
        doReturn(new ArrayList<Entity>()).when(objA).getEntitiesByCategoryAndNotActiveCertificate(entityCategory);
        final List<Entity> entityList = objA.getEntitiesWithInvalidCertificate(null, 0, entityCategory);
    }

    @Test(expected = EntityCategoryNotFoundException.class)
    public void testGetEntitiesByCategoryAndValidityWithWrongCategory() {
        final Date date = new Date();
        final List<Entity> entityList1 = new ArrayList<Entity>();
        for (int i = 0; i < 5; i++) {
            final Entity ent = new Entity();
            final EntityInfo entityInfo = new EntityInfo();
            entityInfo.setId(i);
            ent.setEntityInfo(entityInfo);
            entityList1.add(ent);
        }

        final EntityPersistenceHandler objA = Mockito.spy(entityPersistenceHandler);
        Mockito.when(persistenceManager.findEntityByName(EntityCategoryData.class, entityCategory.getName(), NAME)).thenReturn(null);
        // doReturn(entityList1).when(objA).getEntitiesByCategoryAndCertificateValidity(date, entityCategory);
        doReturn(new ArrayList<Entity>()).when(objA).getEntitiesByCategoryAndNotActiveCertificate(entityCategory);
        final List<Entity> entityList = objA.getEntitiesWithInvalidCertificate(date, 0, entityCategory);
    }

    @Test
    public void testGetEntitiesByStatusWithEmptyList() {
        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("entityInfoData.status", 2);
        when(persistenceManager.findEntitiesWhere(CAEntityData.class, attributes)).thenReturn(null);
        entityPersistenceHandler.getEntitiesByStatus(1);
        assertSame(null, entityPersistenceHandler.getEntitiesByStatus(1));
    }

    @Test(expected = EntityServiceException.class)
    public void testGetEntitiesByStatusWithPersistenceException() {
        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("entityInfoData.status", 2);
        when(persistenceManager.findEntitiesWhere(EntityData.class, attributes)).thenThrow(new javax.persistence.PersistenceException());
        entityPersistenceHandler.getEntitiesByStatus(2);
        // assertSame(null, entityPersistenceHandler.getEntitiesByStatus(1));
    }

    @Test
    public void testGetEntitiesByStatus() {

        final List<Object> entityListExpected = new ArrayList<Object>();
        entityListExpected.add(entity);

        final Map<String, Object> attributes = new HashMap<String, Object>();
        attributes.put("entityInfoData.status", 2);
        when(persistenceManager.findEntitiesWhere(EntityData.class, attributes)).thenReturn(entityDataList);
        when(modelMapper.toAPIModelList(entityDataList)).thenReturn(entityListExpected);

        assertEquals(entityList, entityPersistenceHandler.getEntitiesByStatus(2));

    }

    @Test
    public void testGetEntitiesCountByFilter() {

        final EntitiesFilter entitiesFilter = getEntitiesFilter();
        final StringBuilder whereQueryForEE = new StringBuilder();
        final Map<String, Object> attributes = new HashMap<String, Object>();
        final BigInteger bi2 = BigInteger.valueOf(123L);
        when(entityFilterDynamicQueryBuilder.buildWhereQueryForEE(entitiesFilter, whereQueryForEE, attributes)).thenReturn(attributes);
        when(persistenceManager.findEntityCountByNativeQuery(Matchers.anyString(), Matchers.anyMap())).thenReturn(bi2);
        entityPersistenceHandler.getEntitiesCountByFilter(entitiesFilter);
        entitiesFilter.getType().remove(EntityType.ENTITY);
        entityPersistenceHandler.getEntitiesCountByFilter(entitiesFilter);

    }

    @Test
    public void testUpdateEntityStatusToInactive() {

        when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        when(entityManager.createNativeQuery(Matchers.anyString())).thenReturn(query);
        when(query.executeUpdate()).thenReturn(1);

        entityPersistenceHandler.updateEntityStatusToInactive();

    }

    @Test
    public void testValidateSubjectWithNullEntity() throws Exception {
        entityPersistenceHandler.validateSubject(null);
    }

    @Test
    public void testValidateSubjectWithNullEntityInfo() throws Exception {
        final Entity newEntity = new Entity();
        entityPersistenceHandler.validateSubject(newEntity);
    }

    @Test
    public void testValidateSubjectWithNullEntityIssuer() throws Exception {
        final Entity newEntity = new Entity();
        final EntityInfo newEntityInfo = new EntityInfo();
        newEntityInfo.setId(2);
        final CertificateAuthority issuer = new CertificateAuthority();
        newEntityInfo.setIssuer(issuer);
        final Subject subject = builderSubject();
        newEntityInfo.setSubject(subject);
        newEntity.setEntityInfo(newEntityInfo);
        final Map<String, Object> attributes = new HashMap<String, Object>();
        final String orderedString = SubjectUtils.orderSubjectDN(newEntity.getEntityInfo().getSubject().toASN1String());
        final byte[] subjectDNHash = SubjectUtils.generateSubjectDNHash(orderedString);
        attributes.put(SUBJECT_DN_HASH, subjectDNHash);
        final List<SubjectIdentificationData> entitySubjectDatas = builderEntitySubjectDatas(subjectDNHash);
        when(persistenceManager.findEntitiesWhere(Matchers.any(Class.class), Matchers.anyMap())).thenReturn(entitySubjectDatas);
        final EntityData currentEntityData = createFirstEntity();
        when(persistenceManager.findEntity(EntityData.class, 1)).thenReturn(currentEntityData);

        entityPersistenceHandler.validateSubject(newEntity);
    }

    @Test
    public void testValidateSubjectWithSuccess() throws Exception {
        final EntityData currentEntityData = createFirstEntity();
        final Entity newEntity = new Entity();
        final EntityInfo newEntityInfo = new EntityInfo();
        newEntityInfo.setId(2);
        final CertificateAuthority issuer = new CertificateAuthority();
        issuer.setName(ISSUER_NAME_IPSEC);
        newEntityInfo.setIssuer(issuer);
        final Subject subject = builderSubject();
        newEntityInfo.setSubject(subject);
        newEntity.setEntityInfo(newEntityInfo);
        when(persistenceManager.findEntity(EntityData.class, 1)).thenReturn(currentEntityData);
        final Map<String, Object> attributes = new HashMap<String, Object>();
        final String orderedString = SubjectUtils.orderSubjectDN(newEntity.getEntityInfo().getSubject().toASN1String());
        final byte[] subjectDNHash = SubjectUtils.generateSubjectDNHash(orderedString);
        attributes.put(SUBJECT_DN_HASH, subjectDNHash);
        final List<SubjectIdentificationData> entitySubjectDatas = builderEntitySubjectDatas(subjectDNHash);
        when(persistenceManager.findEntitiesWhere(Matchers.any(Class.class), Matchers.anyMap())).thenReturn(entitySubjectDatas);

        entityPersistenceHandler.validateSubject(newEntity);
    }

    @Test(expected = InvalidSubjectException.class)
    public void testValidateSubjectWithException() throws Exception {
        final EntityData currentEntityData = createFirstEntity();
        final Entity newEntity = new Entity();
        final EntityInfo newEntityInfo = new EntityInfo();
        newEntityInfo.setId(2);
        final CertificateAuthority issuer = new CertificateAuthority();
        issuer.setName(ISSUER_NAME_OAM);
        newEntityInfo.setIssuer(issuer);
        final Subject subject = builderSubject();
        newEntityInfo.setSubject(subject);
        newEntity.setEntityInfo(newEntityInfo);
        when(persistenceManager.findEntity(EntityData.class, 1)).thenReturn(currentEntityData);
        final Map<String, Object> attributes = new HashMap<String, Object>();
        final String orderedString = SubjectUtils.orderSubjectDN(newEntity.getEntityInfo().getSubject().toASN1String());
        final byte[] subjectDNHash = SubjectUtils.generateSubjectDNHash(orderedString);
        attributes.put(SUBJECT_DN_HASH, subjectDNHash);
        final List<SubjectIdentificationData> entitySubjectDatas = builderEntitySubjectDatas(subjectDNHash);
        when(persistenceManager.findEntitiesWhere(Matchers.any(Class.class), Matchers.anyMap())).thenReturn(entitySubjectDatas);

        entityPersistenceHandler.validateSubject(newEntity);
    }

    private List<SubjectIdentificationData> builderEntitySubjectDatas(final byte[] subjectDNHash) {
        final List<SubjectIdentificationData> entitySubjectDatas = new ArrayList<>();
        final SubjectIdentificationData entitySubjectData = new SubjectIdentificationData();
        entitySubjectData.setEntityId(1);
        entitySubjectData.setId(1);
        entitySubjectData.setSubjectDNHash(subjectDNHash);
        entitySubjectDatas.add(entitySubjectData);
        final SubjectIdentificationData entitySubjectData2 = new SubjectIdentificationData();
        entitySubjectData2.setEntityId(2);
        entitySubjectData2.setId(2);
        entitySubjectData2.setSubjectDNHash(subjectDNHash);
        entitySubjectDatas.add(entitySubjectData2);
        return entitySubjectDatas;
    }

    private EntityData createFirstEntity() {
        final EntityData currentEntityData = new EntityData();
        currentEntityData.setId(1);
        final EntityInfoData entityInfoData = new EntityInfoData();
        final CAEntityData caEntitydata = new CAEntityData();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();
        certificateAuthorityData.setName("OAM");
        caEntitydata.setCertificateAuthorityData(certificateAuthorityData);
        entityInfoData.setIssuer(caEntitydata);
        currentEntityData.setEntityInfoData(entityInfoData);
        return currentEntityData;
    }

    private Subject builderSubject() {
        final Subject subject = new Subject();
        final List<SubjectField> entSubjectFieldList = new ArrayList<>();

        final SubjectField subjectFieldCountry = new SubjectField();
        subjectFieldCountry.setType(SubjectFieldType.COUNTRY_NAME);
        subjectFieldCountry.setValue("IT");

        final SubjectField subjectFieldOrg = new SubjectField();
        subjectFieldOrg.setType(SubjectFieldType.ORGANIZATION);
        subjectFieldOrg.setValue("Ericsson");

        entSubjectFieldList.add(subjectFieldCountry);
        entSubjectFieldList.add(subjectFieldOrg);
        subject.setSubjectFields(entSubjectFieldList);
        return subject;
    }

    @Test
    public void testGetEntitiesByCategoryAndNotActiveCertificate() {

        final String qlString = "select e from EntityData e where e.entityCategoryData.id in (:entityCategories)"
                + " and e.entityInfoData.status = :entityStatusInteger"
                + " and e.id not in (select ent.id from EntityData ent inner join ent.entityInfoData.certificateDatas as certificate where certificate.status= :activeStatusInInteger) ";
        Mockito.when(persistenceManager.findEntityByName(EntityCategoryData.class, entityCategory.getName(), NAME)).thenReturn(entityCategoryData);
        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(qlString)).thenReturn(query);
        assertNotNull(entityPersistenceHandler.getEntitiesByCategoryAndNotActiveCertificate(entityCategory));
    }

    @Test
    public void testGetEntityNameByCaNameAndSerialNumber() {
        final EntityData entityData = entityDataList.get(0);
        entityInfoData.setCertificateDatas(certificateDatas);
        entityData.setEntityInfoData(entityInfoData);
        entityDataList.remove(0);
        entityDataList.add(entityData);
        final String qlString = "select e from EntityData e inner join e.entityInfoData.certificateDatas as cdata "
                + " where e.entityProfileData.certificateProfileData in "
                + "(select cp from CertificateProfileData cp where cp.issuerData.certificateAuthorityData.name = :caName )"
                + "  and cdata.serialNumber = :serialNumber ";

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(qlString)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(entityDataList);

        assertNull(entityPersistenceHandler.getEntityNameByCaNameAndSerialNumber(ISSUER_DN, "10101"));

        Mockito.verify(persistenceManager).getEntityManager();
        Mockito.verify(entityManager).createQuery(qlString);
        Mockito.verify(query).getResultList();

    }

    @Test
    public void testGetEntityNameListByCaName() {

        final EntityData entityData = entityDataList.get(0);
        entityInfoData.setCertificateDatas(certificateDatas);
        entityData.setEntityInfoData(entityInfoData);
        entityDataList.remove(0);
        entityDataList.add(entityData);

        final String qlString = "select e from EntityData e  " + " where e.entityProfileData.certificateProfileData in "
                + "(select cp from CertificateProfileData cp where cp.issuerData.certificateAuthorityData.name = :caName )";

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(qlString)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(entityDataList);

        final List<String> expected = new ArrayList<String>();
        expected.add(entityData.getEntityInfoData().getName());
        assertEquals(expected, entityPersistenceHandler.getEntityNameListByCaName(name));
    }

    @Test
    public void testGetEntityNameListByTrustProfile() {
        final EntityData entityData = entityDataList.get(0);
        entityInfoData.setCertificateDatas(certificateDatas);
        entityData.setEntityInfoData(entityInfoData);
        entityDataList.remove(0);
        entityDataList.add(entityData);

        final String qlString =
                "select e from EntityData e " + "inner join e.entityProfileData.trustProfileDatas tp " + " where tp.name = :trustProfileName ";

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(qlString)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(entityDataList);

        final List<String> expected = new ArrayList<String>();
        expected.add(entityData.getEntityInfoData().getName());
        assertEquals(expected, entityPersistenceHandler.getEntityNameListByTrustProfile(name));
    }

    @Test
    public void testSetOtp() {
        entityPersistenceHandler.setOtp(entity);
        Mockito.verify(persistenceManager).updateEntity(entityData);
    }

    @Test(expected = SerialNumberNotFoundException.class)
    public void testGetEntityNameByCaNameAndSerialNumber_SerialNumberNotFoundException() {
        final EntityData entityData = entityDataList.get(0);
        certificateData.setStatus(2);
        entityInfoData.setCertificateDatas(certificateDatas);
        entityData.setEntityInfoData(entityInfoData);
        entityDataList.remove(0);
        entityDataList.add(entityData);
        final String qlString = "select e from EntityData e inner join e.entityInfoData.certificateDatas as cdata "
                + " where e.entityProfileData.certificateProfileData in "
                + "(select cp from CertificateProfileData cp where cp.issuerData.certificateAuthorityData.name = :caName )"
                + "  and cdata.serialNumber = :serialNumber ";

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(qlString)).thenReturn(query);
        Mockito.when(query.getResultList()).thenReturn(entityDataList);

        entityPersistenceHandler.getEntityNameByCaNameAndSerialNumber(ISSUER_DN, SERIAL_NUMBER);
    }

    @Test
    public void testMergeCertificateExpiryNotificationDetails() {
        final Set<CertificateExpiryNotificationDetailsData> certificateExpiryNotificationDetailsDataList =
                new HashSet<CertificateExpiryNotificationDetailsData>();
        certificateExpiryNotificationDetailsDataList.add(certificateExpiryNotificationDetailsData);
        entityData.setCertificateExpiryNotificationDetailsData(certificateExpiryNotificationDetailsDataList);
        entityInfoData.setName("EntityName");
        entityData.setEntityInfoData(entityInfoData);
        final String qlString =
                "select c from CertificateExpiryNotificationDetailsData c where c.id in(select cendd.id from EntityData ed inner join ed.certificateExpiryNotificationDetailsData cendd  WHERE ed.entityInfoData.name = :name and cendd.notificationSeverity= :severity) ORDER BY c.id DESC";

        Mockito.when(persistenceManager.getEntityManager()).thenReturn(entityManager);
        Mockito.when(entityManager.createQuery(qlString)).thenReturn(query);
        Mockito.when(query.getSingleResult()).thenReturn(certificateExpiryNotificationDetailsData);

        assertEquals(certificateExpiryNotificationDetailsDataList, entityPersistenceHandler.mergeCertificateExpiryNotificationDetails(entityData));
    }

    @Test
    public void testGetEntity() {

        Mockito.when(persistenceManager.findEntityByName(EntityData.class, ENTITY_NAME, "entityInfoData.name")).thenReturn(entityData);
        when(entityModelMapper.toApi(entityData, MappingDepth.LEVEL_1)).thenReturn(null);
        assertNull(entityPersistenceHandler.getEntity(SUBJECT_DN, ISSUER_DN));
    }

    @Test(expected = EntityNotFoundException.class)
    public void testgetEntity_NotFound() throws InvalidNameException {

        entityPersistenceHandler.getEntity(SUBJECT_DN, ISSUER_DN);
    }

    @Test
    public void testGetEntityWithNoEntity() {
        final Map<String, Object> attributes = new HashMap<String, Object>();

        final String orderedString = SubjectUtils.orderSubjectDN(SUBJECT_DN);
        final byte[] hash = SubjectUtils.generateSubjectDNHash(orderedString);

        final CAEntityData caEntityData = new CAEntityData();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();

        certificateAuthorityData.setCertificateDatas(certificateDatas);
        caEntityData.setCertificateAuthorityData(certificateAuthorityData);
        entityInfoData.setIssuer(caEntityData);
        entityData.setEntityInfoData(entityInfoData);

        attributes.put("subjectDNHash", hash);
        final List<SubjectIdentificationData> subjects = new ArrayList<>();
        subjects.add(subjectIdentificationData);

        Mockito.when(persistenceManager.findEntityByName(EntityData.class, ENTITY_NAME, "entityInfoData.name")).thenReturn(null);
        when(persistenceManager.findEntitiesWhere(Matchers.any(Class.class), Matchers.anyMap())).thenReturn(subjects);
        when(persistenceManager.findEntity(EntityData.class, subjectIdentificationData.getId())).thenReturn(entityData);

        assertNull(entityPersistenceHandler.getEntity(SUBJECT_DN, ISSUER_DN));
    }

    private EntitiesFilter getEntitiesFilter() {
        final EntitiesFilter entitiesFilter = new EntitiesFilter();

        entitiesFilter.setName("");
        entitiesFilter.setCertificateAssigned(1);

        final List<EntityStatus> status = new ArrayList<EntityStatus>();
        status.add(EntityStatus.ACTIVE);
        entitiesFilter.setStatus(status);
        final List<EntityType> type = new ArrayList<EntityType>();
        type.add(EntityType.ENTITY);
        entitiesFilter.setType(type);
        return entitiesFilter;
    }
}
