/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2013
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.service.validator.caentity;

import static org.mockito.Mockito.*;

import java.util.*;

import javax.persistence.PersistenceException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectAltNameValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectValidator;

@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class UpdateCaEntityNameValidatorTest {
    @Spy
    final Logger logger = LoggerFactory.getLogger(UpdateCaEntityNameValidator.class);

    @InjectMocks
    UpdateCaEntityNameValidator updateCaEntityNameValidator;

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

    CAEntity caEntity;

    CAEntityData caEntityData;

    EntityProfileData entityProfileData;

    SubjectAltName subjectAltName = new SubjectAltName();
    List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();
    SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
    SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
    Map<String, Object> entityProfileMap = new HashMap<String, Object>();
    Map<String, Object> keyGenAlgorithmMap = new HashMap<String, Object>();

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void setup() {

        final EntitiesSetUpData entitiesSetUpData = new EntitiesSetUpData();

        caEntity = entitiesSetUpData.getCaEntity();

        caEntityData = entitiesSetUpData.getCaEntityData();

        entityProfileData = caEntityData.getEntityProfileData();

        entityProfileMap.put("name", "ENMRootCAEntityProfile");
        entityProfileMap.put("active", Boolean.TRUE);

        keyGenAlgorithmMap.put(EntitiesSetUpData.NAME, "RSA");
        keyGenAlgorithmMap.put(EntitiesSetUpData.ALGORITHM_KEY_SIZE, 1024);
        keyGenAlgorithmMap.put(EntitiesSetUpData.ALGORITHM_TYPE, AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);

        when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.CA_ENTITY)).thenReturn(entitiesPersistenceHandler);

        when(entitiesPersistenceHandler.getEntityByName(entityProfileData.getName(), EntityProfileData.class, "name")).thenReturn(entityProfileData);

        when(entitiesPersistenceHandler.getEntityWhere(EntityProfileData.class, entityProfileMap)).thenReturn(entityProfileData);

    }

    /**
     * Method to test validate method in negative scenario. When providing non existing Entity to CertificateAuthority.
     */
    @Test(expected = EntityNotFoundException.class)
    public void testUpdateNotExistingEntity() {

        caEntity.getCertificateAuthority().setName("ENMSubCA");

        when(entitiesPersistenceHandler.getEntityById(1, CAEntityData.class)).thenReturn(null);

        updateCaEntityNameValidator.validate(caEntity);

    }

    /**
     * Method to test validate method in negative scenario. When providing already existing Entity to CertificateAuthority.
     */
    @Test(expected = EntityAlreadyExistsException.class)
    public void testUpdateNameAlreadyExisting() {

        caEntity.getCertificateAuthority().setName("ENMSubCA");

        when(persistenceManager.findEntityByName(CAEntityData.class, "ENMSubCA", EntitiesSetUpData.CA_NAME_PATH)).thenReturn(caEntityData);
        when(entitiesPersistenceHandler.getEntityById(1, CAEntityData.class)).thenReturn(caEntityData);

        updateCaEntityNameValidator.validate(caEntity);

    }

    /**
     * Method to test validate method in negative scenario.
     */
    @Test(expected = EntityServiceException.class)
    public void testUpdateNameEx() {

        caEntity.getCertificateAuthority().setName("ENMSubCA");

        when(entitiesPersistenceHandler.getEntityById(1, CAEntityData.class)).thenReturn(caEntityData);
        when(persistenceManager.findEntityByName(CAEntityData.class, "ENMSubCA", EntitiesSetUpData.CA_NAME_PATH)).thenThrow(new PersistenceException());

        updateCaEntityNameValidator.validate(caEntity);

    }

    /**
     * Method to test validate method in positive scenario whether DB call is happening for at least 1 time.
     */
    @Test
    public void testValidateUpdate() {

        when(entitiesPersistenceHandler.getEntityById(Mockito.anyInt(), Mockito.any(Class.class))).thenReturn(caEntityData);

        updateCaEntityNameValidator.validate(caEntity);

        verify(entitiesPersistenceHandler, times(1)).getEntityById(Mockito.anyInt(), Mockito.any(Class.class));

    }

    /**
     * Method to test validate method in positive scenario whether DB call is happening for at least 1 time.
     */
    @Test
    public void testUpdateValidate() {

        when(entitiesPersistenceHandler.getEntityById(1, CAEntityData.class)).thenReturn(caEntityData);

        updateCaEntityNameValidator.validate(caEntity);

        verify(entitiesPersistenceHandler, times(1)).getEntityById(1, CAEntityData.class);

    }

}
