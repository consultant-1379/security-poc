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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entity;

import static org.mockito.Mockito.*;

import java.util.HashMap;
import java.util.Map;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AbstractSubjectAltNameFieldValue;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectAltNameValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectValidator;

@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class EntityProfileValidatorTest {

    @Spy
    final private Logger logger = LoggerFactory.getLogger(EntityProfileValidator.class);

    @InjectMocks
    EntityProfileValidator entityProfileValidator;

    @Mock
    EntitiesPersistenceHandlerFactory entitiesPersistenceHandlerFactory;

    @Mock
    EntitiesPersistenceHandler entitiesPersistenceHandler;

    @Mock
    SubjectValidator subjectValidator;

    @Mock
    SubjectAltNameValidator subjectAltNameValidator;

    @Mock
    PersistenceManager persistenceManager;

    Entity entity;

    EntityData entityData;

    EntityProfileData entityProfileData;
    Map<String, Object> entityProfileMap = new HashMap<String, Object>();

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public <T extends AbstractSubjectAltNameFieldValue> void setup() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();

        entity = entitiesSetUpData.getEntity();
        entityData = entitiesSetUpData.getEntityData();
        entityProfileData = entityData.getEntityProfileData();
        entityProfileMap.put("name", "ENMRootCAEntityProfile");
        entityProfileMap.put("active", Boolean.TRUE);
        entityProfileData.getCertificateProfileData().setForCAEntity(false);
        when(entitiesPersistenceHandler.getEntityWhere(EntityProfileData.class, entityProfileMap)).thenReturn(entityProfileData);
        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.ENTITY)).thenReturn(entitiesPersistenceHandler);
        when(entitiesPersistenceHandler.getEntityWhere(EntityProfileData.class, entityProfileMap)).thenReturn(entityProfileData);
        when(entitiesPersistenceHandler.getEntityByName(entityProfileData.getName(), EntityProfileData.class, "name")).thenReturn(entityProfileData);
        when(persistenceManager.findEntityByName(EntityCategoryData.class, entity.getCategory().getName(), "name")).thenReturn(entityData.getEntityCategoryData());
    }

    /**
     * Method to test validate method in negative scenario. When isForCAEntity flag is set to true.
     */
    @Test(expected = InvalidProfileException.class)
    public void testWrongEntityProfile() {
        entityData.getEntityProfileData().getCertificateProfileData().setForCAEntity(true);
        entityProfileValidator.validate(entity);

    }

    /**
     * Method to test validate method in negative scenario.When entitiesPersistenceHandler returning null entity data.
     */
    @Test(expected = ProfileNotFoundException.class)
    public void testNullEntityProfile() {
        when(entitiesPersistenceHandler.getEntityWhere(EntityProfileData.class, entityProfileMap)).thenReturn(null);
        entityProfileValidator.validate(entity);

    }

    /**
     * Method to test validate method in negative scenario.When providing EntityProfile is set to Null.
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testCreateEntityProfileNull() {

        entity.setEntityProfile(new EntityProfile());

        entityProfileValidator.validate(entity);

    }

    /**
     * Method to test validate method in negative scenario.When providing EntityProfile is set to Empty.
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testCreateEntityProfileEmpty() {
        entity.setEntityProfile(new EntityProfile());
        entityProfileValidator.validate(entity);

    }

    /**
     * Method to test validate method in negative scenario.When providing EntityProfile is set to Null.
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testEntityProfileNull() {
        entity.setEntityProfile(null);
        entityProfileValidator.validate(entity);

    }

    /**
     * Method to test validate method in negative scenario.When providing EntityProfile is set to Empty.
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testEntityProfileNameEmpty() {

        final EntityProfile entityProfile = new EntityProfile();
        entityProfile.setName("");
        entity.setEntityProfile(entityProfile);
        entityProfileValidator.validate(entity);

    }

    /**
     * Method to test validate method in positive scenario.
     */
    @Test
    public void testValidate() {
        entityProfileValidator.validate(entity);

    }

}
