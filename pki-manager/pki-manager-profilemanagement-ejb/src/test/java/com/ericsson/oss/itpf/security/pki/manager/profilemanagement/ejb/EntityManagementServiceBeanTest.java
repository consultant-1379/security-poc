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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.ejb;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertFalse;
import static org.junit.Assert.assertNotNull;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertTrue;
import static org.mockito.Mockito.doNothing;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.ArrayList;
import java.util.List;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.EntityManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.model.EnrollmentInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.EnrollmentType;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityEnrollmentInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.TreeNode;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustedEntityInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entities;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.EntitiesManager;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.ValidationService;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ItemType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.OperationType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ValidateItem;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.utils.ValidationServiceUtils;

@RunWith(MockitoJUnitRunner.class)
public class EntityManagementServiceBeanTest {

    @InjectMocks
    EntityManagementServiceBean entityManagementServiceBean;

    @Mock
    EntityManagementAuthorizationManager entityManagementAuthorization;

    @Mock
    EntitiesPersistenceHandlerFactory entitiesPersistenceHandlerFactory;

    @Mock
    EntitiesManager entitiesManager;

    @Mock
    Logger logger;

    @Mock
    ValidationServiceUtils validateServiceUtils;

    @Mock
    ValidationService validationService;

    @Mock
    BulkImportLocalServiceBean bulkImportLocalServiceBean;

    @Mock
    SystemRecorder systemRecorder;

    CAEntity caEntity = new CAEntity();
    Entity entity = new Entity();
    Entities entities = new Entities();

    List<CAEntity> caEntitiesList = new ArrayList<CAEntity>();
    List<Entity> entitiesList = new ArrayList<Entity>();
    List<AbstractEntity> entityList = new ArrayList<AbstractEntity>();
    EnrollmentInfo enrollmentInfo = new EnrollmentInfo();
    private static final String OTP = "2ER13SA32SAD2G3";

    ValidateItem validateItem = new ValidateItem();

    @Before
    public void setup() {

        final CertificateAuthority certificateAuthority = new CertificateAuthority();
        certificateAuthority.setId(1);
        certificateAuthority.setName("ENMRootCA");
        caEntity.setCertificateAuthority(certificateAuthority);

        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setId(1);
        entityInfo.setName("ENMService1");
        entity.setEntityInfo(entityInfo);

        entitiesList.add(entity);
        caEntitiesList.add(caEntity);
        entityList.addAll(entitiesList);
        entities.setCAEntities(caEntitiesList);
        entities.setEntities(entitiesList);

    }

    @Test
    public void testImportEntitiesALL() {
        entityManagementAuthorization.authorizeEntityOperations(EntityType.ENTITY, ActionType.IMPORT);
        when(bulkImportLocalServiceBean.importEntities(entities)).thenReturn(entityList);
        entityManagementServiceBean.importEntities(entities);
        verify(bulkImportLocalServiceBean).importEntities(entities);
    }

    @Test
    public void testImportEntities() {

        entityManagementAuthorization.authorizeEntityOperations(EntityType.ENTITY, ActionType.IMPORT);
        entities.setEntities(new ArrayList<Entity>());
        when(bulkImportLocalServiceBean.importEntities(entities)).thenReturn(entityList);
        entityManagementServiceBean.importEntities(entities);
        verify(bulkImportLocalServiceBean).importEntities(entities);
    }

    @Test
    public void testImportCAEntities() {

        entityManagementAuthorization.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.IMPORT);
        entities.setCAEntities(new ArrayList<CAEntity>());
        when(bulkImportLocalServiceBean.importEntities(entities)).thenReturn(entityList);
        entityManagementServiceBean.importEntities(entities);
        verify(bulkImportLocalServiceBean).importEntities(entities);

    }

    @Test
    public void testGetEntities() {

        entityManagementAuthorization.authorizeEntityOperations(EntityType.ENTITY, ActionType.READ);
        final List<EntityType> entityList = new ArrayList<EntityType>();
        entityList.add(EntityType.CA_ENTITY);
        entityList.add(EntityType.ENTITY);

        final Entities endentities = new Entities();
        final Entities caentities = new Entities();

        caentities.setCAEntities(entities.getCAEntities());
        endentities.setEntities(entities.getEntities());

        when(entitiesManager.getEntities(entityList.toArray(new EntityType[entityList.size()]))).thenReturn(entities);

        final Entities entities_both = entityManagementServiceBean.getEntities(entityList.toArray(new EntityType[entityList.size()]));

        assertEquals(entities, entities_both);

    }

    @Test
    public void testGetCAEntitiesOnly() {

        final Entities caEntitiesOnly = new Entities();
        caEntitiesOnly.setCAEntities(entities.getCAEntities());

        entityManagementAuthorization.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.READ);

        final List<EntityType> entityList = new ArrayList<EntityType>();
        entityList.add(EntityType.CA_ENTITY);
        when(entitiesManager.getEntities(entityList.toArray(new EntityType[entityList.size()]))).thenReturn(caEntitiesOnly);

        final Entities caEntities = entityManagementServiceBean.getEntities(entityList.toArray(new EntityType[entityList.size()]));
        assertEquals(caEntitiesOnly, caEntities);

        verify(entitiesManager).getEntities(EntityType.CA_ENTITY);

    }

    @Test
    public void testGetEntitiesNoProfileType() {
        boolean isIllegalArgumentExceptionCaught = false;
        String errorMessage = "";
        try {
            entityManagementAuthorization.authorizeEntityOperations(EntityType.ENTITY, ActionType.READ);
            final List<EntityType> entityList = new ArrayList<EntityType>();
            entityManagementServiceBean.getEntities(entityList.toArray(new EntityType[entityList.size()]));
        } catch (final IllegalArgumentException exception) {
            isIllegalArgumentExceptionCaught = true;
            errorMessage = exception.getMessage();
        }
        assertTrue(isIllegalArgumentExceptionCaught);
        assertEquals(ProfileServiceErrorCodes.NO_ENTITYTYPE_PRESENT, errorMessage);
    }

    @Test
    public void testGetEntitiesOnly() {

        entityManagementAuthorization.authorizeEntityOperations(EntityType.ENTITY, ActionType.READ);
        final Entities endEentitiesOnly = new Entities();
        endEentitiesOnly.setEntities(entities.getEntities());

        final List<EntityType> entityList = new ArrayList<EntityType>();
        entityList.add(EntityType.ENTITY);
        when(entitiesManager.getEntities(entityList.toArray(new EntityType[entityList.size()]))).thenReturn(endEentitiesOnly);

        final Entities endEntities = entityManagementServiceBean.getEntities(EntityType.ENTITY);
        assertEquals(endEentitiesOnly, endEntities);
    }

    @Test
    public void testCreateEntity() {
        entityManagementAuthorization.authorizeEntityOperations(EntityType.ENTITY, ActionType.CREATE);
        when(entitiesManager.createEntity(entity)).thenReturn(entity);
        when(validateServiceUtils.generateEntityValidateItem(EntityType.ENTITY, OperationType.CREATE, entity)).thenReturn(validateItemSetupData(OperationType.CREATE));
        Mockito.doNothing().when(validationService).validate(validateItem);
        final Entity endEntity = entityManagementServiceBean.createEntity(entity);
        assertEquals(entity, endEntity);
    }

    @Test(expected = NullPointerException.class)
    public void testCreateNull() {

        entityManagementAuthorization.authorizeEntityOperations(EntityType.ENTITY, ActionType.CREATE);
        entityManagementServiceBean.createEntity(null);
    }

    @Test
    public void testCreateEntity_v1() {
        entityManagementAuthorization.authorizeEntityOperations(EntityType.ENTITY, ActionType.CREATE);
        when(entitiesManager.createEntity(entity)).thenReturn(entity);
        when(validateServiceUtils.generateEntityValidateItem(EntityType.ENTITY, OperationType.CREATE, entity)).thenReturn(validateItemSetupData(OperationType.CREATE));
        Mockito.doNothing().when(validationService).validate(validateItem);
        final Entity endEntity = entityManagementServiceBean.createEntity_v1(entity);
        assertEquals(entity, endEntity);
    }

    @Test(expected = NullPointerException.class)
    public void testCreateEntity_v1Null() {
        entityManagementAuthorization.authorizeEntityOperations(EntityType.ENTITY, ActionType.CREATE);
        entityManagementServiceBean.createEntity_v1(null);
    }

    @Test
    public void testCreateCAEntity() {

        entityManagementAuthorization.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.CREATE);
        when(entitiesManager.createEntity(caEntity)).thenReturn(caEntity);
        final CAEntity caEntity_dummy = entityManagementServiceBean.createEntity(caEntity);
        assertEquals(caEntity, caEntity_dummy);
    }

    @Test
    public void testUpdateEntity() {

        entityManagementAuthorization.authorizeEntityOperations(EntityType.ENTITY, ActionType.UPDATE);
        when(entitiesManager.updateEntity(entity)).thenReturn(entity);
        final Entity endEntity = entityManagementServiceBean.updateEntity(entity);
        assertEquals(entity, endEntity);
    }

    @Test
    public void testUpdateEntity_v1() {
        entityManagementAuthorization.authorizeEntityOperations(EntityType.ENTITY, ActionType.UPDATE);
        when(entitiesManager.updateEntity(entity)).thenReturn(entity);
        final Entity endEntity = entityManagementServiceBean.updateEntity_v1(entity);
        assertEquals(entity, endEntity);
    }

    @Test
    public void testUpdateCAEntity() {

        entityManagementAuthorization.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.UPDATE);
        when(entitiesManager.updateEntity(caEntity)).thenReturn(caEntity);
        final CAEntity caEntity_dummy = entityManagementServiceBean.updateEntity(caEntity);
        assertEquals(caEntity, caEntity_dummy);
    }

    @Test(expected = NullPointerException.class)
    public void testUpdateNull() {

        entityManagementAuthorization.authorizeEntityOperations(EntityType.ENTITY, ActionType.UPDATE);
        entityManagementServiceBean.updateEntity(null);
    }

    @Test(expected = NullPointerException.class)
    public void testUpdateEntity_v1Null() {
        entityManagementAuthorization.authorizeEntityOperations(EntityType.ENTITY, ActionType.UPDATE);
        entityManagementServiceBean.updateEntity_v1(null);
    }

    @Test
    public void testGetEntity() {

        entityManagementAuthorization.authorizeEntityOperations(EntityType.ENTITY, ActionType.READ);
        when(entitiesManager.getEntity(entity)).thenReturn(entity);
        final Entity endEntity = entityManagementServiceBean.getEntity(entity);
        assertEquals(entity, endEntity);
    }

    @Test
    public void testGetCAEntity() {

        entityManagementAuthorization.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.READ);
        when(entitiesManager.getEntity(caEntity)).thenReturn(caEntity);
        final CAEntity caEntity_dummy = entityManagementServiceBean.getEntity(caEntity);
        assertEquals(caEntity, caEntity_dummy);
    }

    @Test(expected = NullPointerException.class)
    public void testGetEntityNull() {

        entityManagementAuthorization.authorizeEntityOperations(EntityType.ENTITY, ActionType.READ);
        entityManagementServiceBean.getEntity(null);
    }

    @Test
    public void testDeteleEntity() {

        entityManagementAuthorization.authorizeEntityOperations(EntityType.ENTITY, ActionType.DELETE);
        entityManagementServiceBean.deleteEntity(entity);
        verify(entitiesManager).deleteEntity(entity);
    }

    @Test
    public void testDeteleCAEntity() {

        entityManagementAuthorization.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.DELETE);
        entityManagementServiceBean.deleteEntity(caEntity);
        verify(entitiesManager).deleteEntity(caEntity);
    }

    @Test(expected = NullPointerException.class)
    public void testDeleteEntityNull() {

        entityManagementAuthorization.authorizeEntityOperations(EntityType.ENTITY, ActionType.DELETE);
        entityManagementServiceBean.deleteEntity(null);
    }

    @Test
    public void testIsNameAvailableCAEntity() {

        when(entitiesManager.isNameAvailable(caEntity.getCertificateAuthority().getName(), EntityType.CA_ENTITY)).thenReturn(true);
        assertTrue(entityManagementServiceBean.isEntityNameAvailable(caEntity.getCertificateAuthority().getName(), EntityType.CA_ENTITY));
    }

    @Test
    public void testIsNameAvailableCAEntityFlase() {
        when(entitiesManager.isNameAvailable(caEntity.getCertificateAuthority().getName(), EntityType.CA_ENTITY)).thenReturn(false);
        when(entitiesManager.isNameAvailable(caEntity.getCertificateAuthority().getName(), EntityType.CA_ENTITY)).thenReturn(false);
        assertFalse(entityManagementServiceBean.isEntityNameAvailable(caEntity.getCertificateAuthority().getName(), EntityType.CA_ENTITY));
    }

    @Test
    public void testIsNameAvailableEntity() {
        when(entitiesManager.isNameAvailable(entity.getEntityInfo().getName(), EntityType.ENTITY)).thenReturn(true);
        assertTrue(entityManagementServiceBean.isEntityNameAvailable(entity.getEntityInfo().getName(), EntityType.ENTITY));
    }

    @Test
    public void testIsNameAvailableEntityFlase() {
        when(entitiesManager.isNameAvailable(entity.getEntityInfo().getName(), EntityType.ENTITY)).thenReturn(false);
        assertFalse(entityManagementServiceBean.isEntityNameAvailable(entity.getEntityInfo().getName(), EntityType.ENTITY));
    }

    /**
     * This test case is used to verify getEnrollmentInfo method.
     */
    @Test
    public void testGetEnrollmentInfo() {

        when(entitiesManager.getEnrollmentInfoForEntity(entity, EnrollmentType.scep)).thenReturn(enrollmentInfo);
        assertEquals(enrollmentInfo, entityManagementServiceBean.getEnrollmentInfo(EnrollmentType.scep, entity));
    }

    /**
     * This test case is used to verify getOTP method.
     */
    @Test
    public void testGetOTP() {
        when(entityManagementServiceBean.getOTP(EntityType.ENTITY.name())).thenReturn(OTP);
        assertEquals(OTP, entityManagementServiceBean.getOTP(EntityType.ENTITY.name()));
    }

    @Test
    public void testGetEntityNameByIssuerNameAndSerialNumber() {
        when(entityManagementServiceBean.getEntityNameByIssuerNameAndSerialNumber(entity.getEntityInfo().getName(), "12345678")).thenReturn("entity_1");
        assertEquals("entity_1", entityManagementServiceBean.getEntityNameByIssuerNameAndSerialNumber(entity.getEntityInfo().getName(), "12345678"));
    }

    @Test
    public void testGetEntityNameListByIssuerName() {
        final List<String> entityList = new ArrayList<String>();
        entityList.add("entity_1");
        when(entityManagementServiceBean.getEntityNameListByIssuerName(entity.getEntityInfo().getName())).thenReturn(entityList);
        assertEquals(entityList, entityManagementServiceBean.getEntityNameListByIssuerName(entity.getEntityInfo().getName()));
    }

    @Test
    public void testGetEntityNameListByTrustProfileName() {
        final List<String> entityList = new ArrayList<String>();
        entityList.add("entity_1");
        when(entityManagementServiceBean.getEntityNameListByTrustProfileName("TP1")).thenReturn(entityList);
        assertEquals(entityList, entityManagementServiceBean.getEntityNameListByTrustProfileName("TP1"));
    }

    @Test
    public void testGetEntityListByIssuerName() {
        final List<Entity> entityList = new ArrayList<Entity>();
        entityList.add(entity);
        when(entityManagementServiceBean.getEntityListByIssuerName(entity.getEntityInfo().getName())).thenReturn(entityList);
        assertEquals(entityList, entityManagementServiceBean.getEntityListByIssuerName(entity.getEntityInfo().getName()));
    }

    @Test
    public void testIsOtpValid() {

        final String entityName = "entityName";
        doNothing().when(entityManagementAuthorization).authorizeIsOTPValid();
        when(entitiesManager.isOTPValid(entityName, OTP)).thenReturn(true);

        assertTrue(entityManagementServiceBean.isOTPValid(entityName, OTP));
    }

    @Test
    public void testGetEntitiesBySubject() {
        final Subject subject = new Subject();
        final EntityType entityType = EntityType.CA_ENTITY;
        assertNull(entityManagementServiceBean.getEntitiesBySubject(subject, entityType));
    }

    @Test
    public void testDeleteEntities() {

        entityManagementAuthorization.authorizeEntityOperations(EntityType.ENTITY, ActionType.DELETE);
        doNothing().when(entitiesManager).deleteEntites(entities);

        entityManagementServiceBean.deleteEntities(entities);

        verify(logger).debug("Deleting Entities in Bulk");
    }

    @Test
    public void testUpdateEntities() {

        entityManagementAuthorization.authorizeEntityOperations(EntityType.ENTITY, ActionType.UPDATE);
        doNothing().when(entitiesManager).updateEntities(entities);

        entityManagementServiceBean.updateEntities(entities);

        verify(logger).debug("Updating Entities in Bulk");
    }

    @Test
    public void testUpdateOtp() {
        final String entityName = "entityName";
        final int oTPCount = 1;
        doNothing().when(entitiesManager).updateOTP(entity);

        entityManagementServiceBean.updateOTP(entityName, OTP, oTPCount);
    }

    @Test
    public void testUpdateOtp_v1() {
        final String entityName = "entityName";
        final int oTPCount = 1;
        final int otpValidityPeriod = 30;
        doNothing().when(entitiesManager).updateOTP(entity);

        entityManagementServiceBean.updateOTP(entityName, OTP, oTPCount, otpValidityPeriod);
    }

    @Test
    public void testGetOtp() {
        final String entityName = "entityName";
        final String otp = "Some Otp";

        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setName(entityName);

        final Entity entity = new Entity();
        entity.setEntityInfo(entityInfo);
        when(entitiesManager.getOtp(entity)).thenReturn(otp);

        assertEquals(otp, entityManagementServiceBean.getOTP(entityName));
    }

    @Test
    public void testGetEntitiesByCategory() {
        final EntityCategory entityCategory = new EntityCategory();

        when(entitiesManager.getEntitiesByCategory(entityCategory, true)).thenReturn(entitiesList);

        final List<Entity> entityList = entityManagementServiceBean.getEntitiesByCategory(entityCategory);

        assertEquals(entitiesList.get(0).getEntityInfo(), entityList.get(0).getEntityInfo());
        assertEquals(entitiesList.get(0).getType(), entityList.get(0).getType());
    }

    @Test
    public void testGetTrustDistributionPointUrl() {
        final String url = "Some URL";
        when(entitiesManager.getTrustDistributionPointUrl(entity, "issuer_123", CertificateStatus.ACTIVE)).thenReturn(url);

        assertEquals(url, entityManagementServiceBean.getTrustDistributionPointUrl(entity, "issuer_123", CertificateStatus.ACTIVE));
    }

    /**
     *
     * @param operationType
     *            Type of operation whether create/update
     * @return ValidateItem
     */
    private ValidateItem validateItemSetupData(final OperationType operationType) {
        validateItem.setItem(EntityType.ENTITY);
        validateItem.setItemType(ItemType.ENTITY);
        validateItem.setOperationType(operationType);
        return validateItem;

    }

    @Test
    public void testGetTrustDistributionPoint() {
        final EntityType entityType = EntityType.CA_ENTITY;
        final List<TrustedEntityInfo> trustDistributionPointInfo = new ArrayList<TrustedEntityInfo>();
        when(entitiesManager.getTrustedEntityInfosByTypeAndStatus(entityType, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE)).thenReturn(trustDistributionPointInfo);
        assertEquals(trustDistributionPointInfo, entityManagementServiceBean.getTrustedEntitiesInfo(entityType));
    }

    @Test
    public void testGetTrustDistributionPointInfo() {
        final EntityType entityType = EntityType.CA_ENTITY;
        final String entityName = "entityName";
        final List<TrustedEntityInfo> trustDistributionPointInfo = new ArrayList<TrustedEntityInfo>();
        when(entitiesManager.getTrustedEntityInfosByTypeAndName(entityType, entityName)).thenReturn(trustDistributionPointInfo);
        assertEquals(trustDistributionPointInfo, entityManagementServiceBean.getTrustedEntitiesInfo(entityType, entityName));
    }

    @Test
    public void testGetTrustDistributionPointInfoStatus() {
        final EntityType entityType = EntityType.CA_ENTITY;
        final CertificateStatus certificateStatus = CertificateStatus.ACTIVE;
        final List<TrustedEntityInfo> trustDistributionPointInfo = new ArrayList<TrustedEntityInfo>();
        when(entitiesManager.getTrustedEntityInfosByTypeAndStatus(entityType, certificateStatus)).thenReturn(trustDistributionPointInfo);
        assertEquals(trustDistributionPointInfo, entityManagementServiceBean.getTrustedEntitiesInfo(entityType, certificateStatus));

    }

    @Test
    public void testgetCAHierarchies() {

        final List<TreeNode<CAEntity>> cAHierarchy = new ArrayList<TreeNode<CAEntity>>();
        when(entitiesManager.getCAHierarchies()).thenReturn(cAHierarchy);
        entityManagementServiceBean.getCAHierarchies();
        assertNotNull(cAHierarchy);
    }

    @Test
    public void testgetCAHierarchiesByName() {
        final TreeNode<CAEntity> cAHierarchy = new TreeNode<CAEntity>();
        when(entitiesManager.getCAHierarchyByName("testName")).thenReturn(cAHierarchy);
        entityManagementServiceBean.getCAHierarchyByName("testName");
        assertNotNull(cAHierarchy);
    }

    @Test
    public void testCreateEntityAndGetEnrollmentInfo() {
        final EntityEnrollmentInfo entityEnrollmentInfo = entityManagementServiceBean.createEntityAndGetEnrollmentInfo(entity, EnrollmentType.scep);
        when(validateServiceUtils.generateEntityValidateItem(EntityType.ENTITY, OperationType.CREATE, entity)).thenReturn(validateItemSetupData(OperationType.CREATE));
        Mockito.doNothing().when(validationService).validate(validateItem);
        when(entitiesManager.createEntity(entity)).thenReturn(entity);

        assertNotNull(entityEnrollmentInfo);
    }

    @Test
    public void testCreateEntityAndGetEnrollmentInfo_v1() {
        final EntityEnrollmentInfo entityEnrollmentInfo = entityManagementServiceBean.createEntityAndGetEnrollmentInfo_v1(entity, EnrollmentType.scep);
        when(validateServiceUtils.generateEntityValidateItem(EntityType.ENTITY, OperationType.CREATE, entity)).thenReturn(validateItemSetupData(OperationType.CREATE));
        Mockito.doNothing().when(validationService).validate(validateItem);

        when(entitiesManager.createEntity(entity)).thenReturn(entity);

        assertNotNull(entityEnrollmentInfo);
    }

    @Test
    public void testUpdateEntityAndGetEnrollmentInfo() {

        when(entitiesManager.updateEntity(entity)).thenReturn(entity);
        final EntityEnrollmentInfo entityEnrollmentInfo = entityManagementServiceBean.updateEntityAndGetEnrollmentInfo(entity, EnrollmentType.scep);
        assertNotNull(entityEnrollmentInfo);

    }

    @Test
    public void testUpdateEntityAndGetEnrollmentInfo_v1() {

        when(entitiesManager.updateEntity(entity)).thenReturn(entity);
        final EntityEnrollmentInfo entityEnrollmentInfo = entityManagementServiceBean.updateEntityAndGetEnrollmentInfo_v1(entity, EnrollmentType.scep);
        assertNotNull(entityEnrollmentInfo);

    }
}
