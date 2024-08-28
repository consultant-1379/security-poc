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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.ejb;

import static org.junit.Assert.assertNotNull;
import static org.mockito.Mockito.when;

import java.util.List;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.ModelMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.EntitiesModelMapperFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.data.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.EntitiesManager;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.ValidationService;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.*;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.utils.ValidationServiceUtils;

@RunWith(MockitoJUnitRunner.class)
public class BulkImportLocalServiceBeanTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(BulkImportLocalServiceBean.class);

    @InjectMocks
    BulkImportLocalServiceBean bulkImportLocalServiceBean;

    @Mock
    ValidationServiceUtils validateServiceUtils;

    @Mock
    ValidationService validationService;

    @Mock
    EntitiesPersistenceHandlerFactory entitiesPersistenceHandlerFactory;

    @Mock
    EntitiesModelMapperFactory entitiesModelMapperFactory;

    @Mock
    ModelMapper entitiesMapper;

    @Mock
    ModelMapper caentitiesMapper;

    @Mock
    EntitiesManager entitiesManager;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    EntityPersistenceHandler<Entity> entityPersistenceHandler;

    ValidateItem validateItem = new ValidateItem();

    Entity entity;
    CAEntity caEntity;
    Entities entities = new Entities();
    List<Entity> entityList;

    List<CAEntity> caEntityList;

    @Test
    public void testimportEntities() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entityList = entitiesSetUpData.getEntityList();
        entity = entityList.get(0);
        entities.setEntities(entityList);

        final List<EntityData> entityDataList1 = entitiesSetUpData.getEntityDataList();

        when(validateServiceUtils.generateEntityValidateItem(EntityType.ENTITY, OperationType.CREATE, entity)).thenReturn(validateItemSetupData(OperationType.CREATE));
        Mockito.doNothing().when(validationService).validate(validateItem);

        when(entitiesModelMapperFactory.getEntitiesMapper(EntityType.ENTITY)).thenReturn(entitiesMapper);

        when(entitiesMapper.fromAPIToModel(entity)).thenReturn(entityDataList1.get(0));

        when(entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.ENTITY)).thenReturn(entityDataList1.get(0));

        when(entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.CA_ENTITY)).thenReturn(entityDataList1.get(0));

        when((EntityPersistenceHandler<Entity>) entitiesManager.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entityPersistenceHandler);

        final List<AbstractEntity> validEntities = bulkImportLocalServiceBean.importEntities(entities);
        assertNotNull(validEntities);
    }

    @Test
    public void testImportCAEntities() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        final Entities entitiesloc = new Entities();
        caEntityList = entitiesSetUpData.getCaEntityList();
        caEntity = caEntityList.get(0);

        entitiesloc.setCAEntities(caEntityList);

        final List<CAEntityData> caentityDataList1 = entitiesSetUpData.getCaEntityDataList();

        when(validateServiceUtils.generateEntityValidateItem(EntityType.CA_ENTITY, OperationType.CREATE, entity)).thenReturn(validateItemSetupData(OperationType.CREATE));
        Mockito.doNothing().when(validationService).validate(validateItem);

        when(entitiesModelMapperFactory.getEntitiesMapper(EntityType.CA_ENTITY)).thenReturn(caentitiesMapper);

        when(caentitiesMapper.fromAPIToModel(caEntity)).thenReturn(caentityDataList1.get(0));

        when(entitiesManager.persistEntityData(caentityDataList1.get(0), EntityType.CA_ENTITY)).thenReturn(caentityDataList1.get(0));

        when(entitiesManager.persistEntityData(caentityDataList1.get(0), EntityType.CA_ENTITY)).thenReturn(caentityDataList1.get(0));

        final List<AbstractEntity> validEntities = bulkImportLocalServiceBean.importEntities(entitiesloc);
        assertNotNull(validEntities);
    }

    @Test(expected = NullPointerException.class)
    public void testimportCAEntitieswithNullPointerException() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        final List<CAEntity> caentityList = entitiesSetUpData.getCaEntityList();
        caEntity = caentityList.get(0);
        entities.setCAEntities(caentityList);

        final List<CAEntityData> caentityDataList1 = entitiesSetUpData.getCaEntityDataList();

        when(validateServiceUtils.generateEntityValidateItem(EntityType.CA_ENTITY, OperationType.CREATE, entity)).thenReturn(validateItemSetupData(OperationType.CREATE));

        Mockito.doNothing().when(validationService).validate(validateItem);

        when(entitiesModelMapperFactory.getEntitiesMapper(EntityType.CA_ENTITY)).thenReturn(caentitiesMapper);

        when(entitiesManager.persistEntityData(caentityDataList1.get(0), EntityType.CA_ENTITY)).thenReturn(caentityDataList1.get(0));

        final List<AbstractEntity> validEntities = bulkImportLocalServiceBean.importEntities(entities);

    }

    @Test(expected = AlgorithmNotFoundException.class)
    public <E extends AbstractEntityData> void testimportEntitiesThrowsExceptioTest() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entityList = entitiesSetUpData.getEntityList();
        entity = entityList.get(0);
        entities.setEntities(entityList);

        final List<EntityData> entityDataList1 = entitiesSetUpData.getEntityDataList();

        when(validateServiceUtils.generateEntityValidateItem(EntityType.ENTITY, OperationType.CREATE, entity)).thenReturn(validateItemSetupData(OperationType.CREATE));

        Mockito.doThrow(AlgorithmNotFoundException.class).when(validationService).validate(validateItem);

        when(entitiesModelMapperFactory.getEntitiesMapper(EntityType.ENTITY)).thenReturn(entitiesMapper);

        when((E) entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.ENTITY)).thenReturn((E) entityDataList1.get(0));

        when(entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.CA_ENTITY)).thenReturn(entityDataList1.get(0));

        final List<AbstractEntity> validEntities = bulkImportLocalServiceBean.importEntities(entities);

    }

    @Test(expected = EntityAlreadyExistsException.class)
    public <E extends AbstractEntityData> void testimportEntitiesThrowsEntityAlreadyExistsException() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entityList = entitiesSetUpData.getEntityList();
        entity = entityList.get(0);
        entities.setEntities(entityList);

        final List<EntityData> entityDataList1 = entitiesSetUpData.getEntityDataList();

        when(validateServiceUtils.generateEntityValidateItem(EntityType.ENTITY, OperationType.CREATE, entity)).thenReturn(validateItemSetupData(OperationType.CREATE));

        Mockito.doThrow(EntityAlreadyExistsException.class).when(validationService).validate(validateItem);

        when(entitiesModelMapperFactory.getEntitiesMapper(EntityType.ENTITY)).thenReturn(entitiesMapper);

        when((E) entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.ENTITY)).thenReturn((E) entityDataList1.get(0));

        when(entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.CA_ENTITY)).thenReturn(entityDataList1.get(0));

        final List<AbstractEntity> validEntities = bulkImportLocalServiceBean.importEntities(entities);

    }

    @Test(expected = InvalidProfileException.class)
    public <E extends AbstractEntityData> void testimportEntitiesThrowsInvalidProfileException() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entityList = entitiesSetUpData.getEntityList();
        entity = entityList.get(0);
        entities.setEntities(entityList);

        final List<EntityData> entityDataList1 = entitiesSetUpData.getEntityDataList();

        when(validateServiceUtils.generateEntityValidateItem(EntityType.ENTITY, OperationType.CREATE, entity)).thenReturn(validateItemSetupData(OperationType.CREATE));

        Mockito.doThrow(InvalidProfileException.class).when(validationService).validate(validateItem);

        when(entitiesModelMapperFactory.getEntitiesMapper(EntityType.ENTITY)).thenReturn(entitiesMapper);

        when((E) entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.ENTITY)).thenReturn((E) entityDataList1.get(0));

        when(entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.CA_ENTITY)).thenReturn(entityDataList1.get(0));

        final List<AbstractEntity> validEntities = bulkImportLocalServiceBean.importEntities(entities);

    }

    @Test(expected = EntityCategoryNotFoundException.class)
    public <E extends AbstractEntityData> void testimportEntitiesThrowsEntityCategoryNotFoundException() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entityList = entitiesSetUpData.getEntityList();
        entity = entityList.get(0);
        entities.setEntities(entityList);

        final List<EntityData> entityDataList1 = entitiesSetUpData.getEntityDataList();

        when(validateServiceUtils.generateEntityValidateItem(EntityType.ENTITY, OperationType.CREATE, entity)).thenReturn(validateItemSetupData(OperationType.CREATE));

        Mockito.doThrow(EntityCategoryNotFoundException.class).when(validationService).validate(validateItem);

        when(entitiesModelMapperFactory.getEntitiesMapper(EntityType.ENTITY)).thenReturn(entitiesMapper);

        when((E) entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.ENTITY)).thenReturn((E) entityDataList1.get(0));

        when(entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.CA_ENTITY)).thenReturn(entityDataList1.get(0));

        final List<AbstractEntity> validEntities = bulkImportLocalServiceBean.importEntities(entities);

    }

    @Test(expected = EntityServiceException.class)
    public <E extends AbstractEntityData> void testimportEntitiesThrowsEntityServiceException() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entityList = entitiesSetUpData.getEntityList();
        entity = entityList.get(0);
        entities.setEntities(entityList);

        final List<EntityData> entityDataList1 = entitiesSetUpData.getEntityDataList();

        when(validateServiceUtils.generateEntityValidateItem(EntityType.ENTITY, OperationType.CREATE, entity)).thenReturn(validateItemSetupData(OperationType.CREATE));

        Mockito.doThrow(EntityServiceException.class).when(validationService).validate(validateItem);

        when(entitiesModelMapperFactory.getEntitiesMapper(EntityType.ENTITY)).thenReturn(entitiesMapper);

        when((E) entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.ENTITY)).thenReturn((E) entityDataList1.get(0));

        when(entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.CA_ENTITY)).thenReturn(entityDataList1.get(0));

        final List<AbstractEntity> validEntities = bulkImportLocalServiceBean.importEntities(entities);

    }

    @Test(expected = InvalidEntityAttributeException.class)
    public <E extends AbstractEntityData> void testimportEntitiesThrowsInvalidEntityAttributeException() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entityList = entitiesSetUpData.getEntityList();
        entity = entityList.get(0);
        entities.setEntities(entityList);

        final List<EntityData> entityDataList1 = entitiesSetUpData.getEntityDataList();

        when(validateServiceUtils.generateEntityValidateItem(EntityType.ENTITY, OperationType.CREATE, entity)).thenReturn(validateItemSetupData(OperationType.CREATE));

        Mockito.doThrow(InvalidEntityAttributeException.class).when(validationService).validate(validateItem);

        when(entitiesModelMapperFactory.getEntitiesMapper(EntityType.ENTITY)).thenReturn(entitiesMapper);

        when((E) entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.ENTITY)).thenReturn((E) entityDataList1.get(0));

        when(entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.CA_ENTITY)).thenReturn(entityDataList1.get(0));

        final List<AbstractEntity> validEntities = bulkImportLocalServiceBean.importEntities(entities);

    }

    @Test(expected = InvalidEntityCategoryException.class)
    public <E extends AbstractEntityData> void testimportEntitiesThrowsInvalidEntityCategoryException() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entityList = entitiesSetUpData.getEntityList();
        entity = entityList.get(0);
        entities.setEntities(entityList);

        final List<EntityData> entityDataList1 = entitiesSetUpData.getEntityDataList();

        when(validateServiceUtils.generateEntityValidateItem(EntityType.ENTITY, OperationType.CREATE, entity)).thenReturn(validateItemSetupData(OperationType.CREATE));

        Mockito.doThrow(InvalidEntityCategoryException.class).when(validationService).validate(validateItem);

        when(entitiesModelMapperFactory.getEntitiesMapper(EntityType.ENTITY)).thenReturn(entitiesMapper);

        when((E) entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.ENTITY)).thenReturn((E) entityDataList1.get(0));

        when(entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.CA_ENTITY)).thenReturn(entityDataList1.get(0));

        final List<AbstractEntity> validEntities = bulkImportLocalServiceBean.importEntities(entities);

    }

    @Test(expected = MissingMandatoryFieldException.class)
    public <E extends AbstractEntityData> void testimportEntitiesThrowsInvalidMissingMandatoryFieldException() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entityList = entitiesSetUpData.getEntityList();
        entity = entityList.get(0);
        entities.setEntities(entityList);

        final List<EntityData> entityDataList1 = entitiesSetUpData.getEntityDataList();

        when(validateServiceUtils.generateEntityValidateItem(EntityType.ENTITY, OperationType.CREATE, entity)).thenReturn(validateItemSetupData(OperationType.CREATE));

        Mockito.doThrow(MissingMandatoryFieldException.class).when(validationService).validate(validateItem);

        when(entitiesModelMapperFactory.getEntitiesMapper(EntityType.ENTITY)).thenReturn(entitiesMapper);

        when((E) entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.ENTITY)).thenReturn((E) entityDataList1.get(0));

        when(entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.CA_ENTITY)).thenReturn(entityDataList1.get(0));

        final List<AbstractEntity> validEntities = bulkImportLocalServiceBean.importEntities(entities);

    }

    @Test(expected = EntityServiceException.class)
    public <E extends AbstractEntityData> void testimportEntitiesThrowsInvalidInvalidSubjectException() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entityList = entitiesSetUpData.getEntityList();
        entity = entityList.get(0);
        entities.setEntities(entityList);

        final List<EntityData> entityDataList1 = entitiesSetUpData.getEntityDataList();

        when(validateServiceUtils.generateEntityValidateItem(EntityType.ENTITY, OperationType.CREATE, entity)).thenReturn(validateItemSetupData(OperationType.CREATE));

        Mockito.doThrow(InvalidSubjectException.class).when(validationService).validate(validateItem);

        when(entitiesModelMapperFactory.getEntitiesMapper(EntityType.ENTITY)).thenReturn(entitiesMapper);

        when((E) entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.ENTITY)).thenReturn((E) entityDataList1.get(0));

        when(entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.CA_ENTITY)).thenReturn(entityDataList1.get(0));

        final List<AbstractEntity> validEntities = bulkImportLocalServiceBean.importEntities(entities);

    }

    @Test(expected = InvalidSubjectAltNameExtension.class)
    public <E extends AbstractEntityData> void testimportEntitiesThrowsInvalidSubjectAltNameExtension() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entityList = entitiesSetUpData.getEntityList();
        entity = entityList.get(0);
        entities.setEntities(entityList);

        final List<EntityData> entityDataList1 = entitiesSetUpData.getEntityDataList();

        when(validateServiceUtils.generateEntityValidateItem(EntityType.ENTITY, OperationType.CREATE, entity)).thenReturn(validateItemSetupData(OperationType.CREATE));

        Mockito.doThrow(InvalidSubjectAltNameExtension.class).when(validationService).validate(validateItem);

        when(entitiesModelMapperFactory.getEntitiesMapper(EntityType.ENTITY)).thenReturn(entitiesMapper);

        when((E) entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.ENTITY)).thenReturn((E) entityDataList1.get(0));

        when(entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.CA_ENTITY)).thenReturn(entityDataList1.get(0));

        final List<AbstractEntity> validEntities = bulkImportLocalServiceBean.importEntities(entities);

    }

    @Test(expected = ProfileNotFoundException.class)
    public <E extends AbstractEntityData> void testimportEntitiesThrowsProfileNotFoundException() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entityList = entitiesSetUpData.getEntityList();
        entity = entityList.get(0);
        entities.setEntities(entityList);

        final List<EntityData> entityDataList1 = entitiesSetUpData.getEntityDataList();

        when(validateServiceUtils.generateEntityValidateItem(EntityType.ENTITY, OperationType.CREATE, entity)).thenReturn(validateItemSetupData(OperationType.CREATE));

        Mockito.doThrow(ProfileNotFoundException.class).when(validationService).validate(validateItem);

        when(entitiesModelMapperFactory.getEntitiesMapper(EntityType.ENTITY)).thenReturn(entitiesMapper);

        when((E) entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.ENTITY)).thenReturn((E) entityDataList1.get(0));

        when(entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.CA_ENTITY)).thenReturn(entityDataList1.get(0));

        final List<AbstractEntity> validEntities = bulkImportLocalServiceBean.importEntities(entities);

    }

    @Test(expected = UnsupportedCRLVersionException.class)
    public <E extends AbstractEntityData> void testimportEntitiesThrowsUnsupportedCRLVersionException() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entityList = entitiesSetUpData.getEntityList();
        entity = entityList.get(0);
        entities.setEntities(entityList);

        final List<EntityData> entityDataList1 = entitiesSetUpData.getEntityDataList();

        when(validateServiceUtils.generateEntityValidateItem(EntityType.ENTITY, OperationType.CREATE, entity)).thenReturn(validateItemSetupData(OperationType.CREATE));

        Mockito.doThrow(UnsupportedCRLVersionException.class).when(validationService).validate(validateItem);

        when(entitiesModelMapperFactory.getEntitiesMapper(EntityType.ENTITY)).thenReturn(entitiesMapper);

        when((E) entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.ENTITY)).thenReturn((E) entityDataList1.get(0));

        when(entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.CA_ENTITY)).thenReturn(entityDataList1.get(0));

        final List<AbstractEntity> validEntities = bulkImportLocalServiceBean.importEntities(entities);

    }

    @Test(expected = CRLExtensionException.class)
    public <E extends AbstractEntityData> void testimportEntitiesThrowsCRLExtensionException() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entityList = entitiesSetUpData.getEntityList();
        entity = entityList.get(0);
        entities.setEntities(entityList);

        final List<EntityData> entityDataList1 = entitiesSetUpData.getEntityDataList();

        when(validateServiceUtils.generateEntityValidateItem(EntityType.ENTITY, OperationType.CREATE, entity)).thenReturn(validateItemSetupData(OperationType.CREATE));

        Mockito.doThrow(CRLExtensionException.class).when(validationService).validate(validateItem);

        when(entitiesModelMapperFactory.getEntitiesMapper(EntityType.ENTITY)).thenReturn(entitiesMapper);

        when((E) entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.ENTITY)).thenReturn((E) entityDataList1.get(0));

        when(entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.CA_ENTITY)).thenReturn(entityDataList1.get(0));

        final List<AbstractEntity> validEntities = bulkImportLocalServiceBean.importEntities(entities);

    }

    @Test(expected = InvalidCRLGenerationInfoException.class)
    public <E extends AbstractEntityData> void testimportEntitiesThrowsInvalidCRLGenerationInfoException() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entityList = entitiesSetUpData.getEntityList();
        entity = entityList.get(0);
        entities.setEntities(entityList);

        final List<EntityData> entityDataList1 = entitiesSetUpData.getEntityDataList();

        when(validateServiceUtils.generateEntityValidateItem(EntityType.ENTITY, OperationType.CREATE, entity)).thenReturn(validateItemSetupData(OperationType.CREATE));

        Mockito.doThrow(InvalidCRLGenerationInfoException.class).when(validationService).validate(validateItem);

        when(entitiesModelMapperFactory.getEntitiesMapper(EntityType.ENTITY)).thenReturn(entitiesMapper);

        when((E) entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.ENTITY)).thenReturn((E) entityDataList1.get(0));

        when(entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.CA_ENTITY)).thenReturn(entityDataList1.get(0));

        final List<AbstractEntity> validEntities = bulkImportLocalServiceBean.importEntities(entities);

    }

    @Test(expected = EntityServiceException.class)
    public void testimportEntitiesThrowsException() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();
        entityList = entitiesSetUpData.getEntityList();
        entity = entityList.get(0);
        entities.setEntities(entityList);

        final List<EntityData> entityDataList1 = entitiesSetUpData.getEntityDataList();

        when(validateServiceUtils.generateEntityValidateItem(EntityType.ENTITY, OperationType.CREATE, entity)).thenReturn(validateItemSetupData(OperationType.CREATE));
        Mockito.doNothing().when(validationService).validate(validateItem);

        when(entitiesModelMapperFactory.getEntitiesMapper(EntityType.ENTITY)).thenReturn(entitiesMapper);

        when(entitiesMapper.fromAPIToModel(entity)).thenReturn(entityDataList1.get(0));

        when(entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.ENTITY)).thenThrow(EntityServiceException.class);

        when(entitiesManager.persistEntityData(entityDataList1.get(0), EntityType.CA_ENTITY)).thenReturn(entityDataList1.get(0));

        final List<AbstractEntity> validEntities = bulkImportLocalServiceBean.importEntities(entities);

    }

    private ValidateItem validateItemSetupData(final OperationType operationType) {
        validateItem.setItem(EntityType.ENTITY);
        validateItem.setItemType(ItemType.ENTITY);
        validateItem.setOperationType(operationType);
        return validateItem;

    }

}
