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
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AbstractSubjectAltNameFieldValue;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectAltNameValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectValidator;

@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class UpdateEntityNameValidatorTest {
    @Spy
    final private Logger logger = LoggerFactory.getLogger(UpdateEntityNameValidatorTest.class);

    @InjectMocks
    UpdateEntityNameValidator updateEntityNameValidator;

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
     * Method to test validate method in positive scenario whether entitiesPersistenceHandler is getting called or not.
     */
    @Test
    public void testValidateUpdate() {
        when(entitiesPersistenceHandler.getEntityById(1, EntityData.class)).thenReturn(entityData);
        updateEntityNameValidator.validate(entity);
        verify(entitiesPersistenceHandler, times(1)).getEntityById(1, EntityData.class);

    }

    /**
     * Method to test validate method in negative scenario.When entitiesPersistenceHandler returning null Entity data.
     */
    @Test(expected = EntityNotFoundException.class)
    public void testValidateUpdateNoEntity() {
        when(entitiesPersistenceHandler.getEntityById(1, EntityData.class)).thenReturn(null);
        updateEntityNameValidator.validate(entity);
    }

}
