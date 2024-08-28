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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.caentity;

import static org.mockito.Mockito.when;

import java.util.*;

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
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.*;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntitiesSetUpData;

@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class CaEntityKeyGenerationAlgorithmValidatorTest {

    @InjectMocks
    CaEntityKeyGenerationAlgorithm caEntityKeyGenerationAlgorithm;

    @Spy
    final Logger logger = LoggerFactory.getLogger(CaEntityKeyGenerationAlgorithm.class);

    @Mock
    EntitiesPersistenceHandlerFactory entitiesPersistenceHandlerFactory;

    @Mock
    EntitiesPersistenceHandler entitiesPersistenceHandler;

    @Mock
    CAEntityPersistenceHandler CAEntityPersistenceHandler;

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
        when(entitiesPersistenceHandler.getEntityByName(entityProfileData.getName(), EntityProfileData.class, "name")).thenReturn(entityProfileData);
        when(entitiesPersistenceHandler.getEntityWhere(EntityProfileData.class, entityProfileMap)).thenReturn(entityProfileData);

        Mockito.when(entitiesPersistenceHandlerFactory.getEntitiesPersistenceHandler(EntityType.CA_ENTITY)).thenReturn(entitiesPersistenceHandler);
    }

    /**
     * Method to test validate method in negative scenario. When KeyGenerationAlgorithm is set to null in CAEntity.
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateCaEntityKeyGenerationAlgorithm() {
        when(entitiesPersistenceHandler.getEntityWhere(EntityProfileData.class, entityProfileMap)).thenReturn(entityProfileData);
        caEntity.setKeyGenerationAlgorithm(null);
        caEntityKeyGenerationAlgorithm.validate(caEntity);

    }

    /**
     * Method to test validate method in negative scenario. When KeyGenerationAlgorithm is set to null in EntityProfileData.
     */
    @Test(expected = AlgorithmNotFoundException.class)
    public void testValidateAlgorithmNotInProfiles() {

        entityProfileData.setKeyGenerationAlgorithm(null);
        entityProfileData.getCertificateProfileData().setKeyGenerationAlgorithms(null);

        when(entitiesPersistenceHandler.getEntityWhere(AlgorithmData.class, keyGenAlgorithmMap)).thenReturn(caEntityData.getKeyGenerationAlgorithm());

        when(entitiesPersistenceHandler.getEntityByName("ENMRootCA", CAEntityData.class, "name")).thenReturn(null);

        caEntityKeyGenerationAlgorithm.validate(caEntity);

    }

    /**
     * Method to test validate method in negative scenario. When KeyGenerationAlgorithm is set to Empty String.
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateAlgorithmEmpty() {

        caEntity.getKeyGenerationAlgorithm().setName(" ");

        caEntityKeyGenerationAlgorithm.validate(caEntity);

    }

    /**
     * Method to test validate method to verify database call is happening or not with null KeyGenerationAlgorithm.
     */
    @Test
    public void testValidateAlgorithmFromCertProfile() {

        entityProfileData.setKeyGenerationAlgorithm(null);

        caEntityKeyGenerationAlgorithm.validate(caEntity);

        Mockito.verify(entitiesPersistenceHandler, Mockito.times(1)).getEntityWhere(EntityProfileData.class, entityProfileMap);

    }

    /**
     * Method to test validate method in negative scenario. When EntityData is set to Null
     */

    @Test(expected = ProfileNotFoundException.class)
    public void testCreateEntityProfileNotFound() {

        when(entitiesPersistenceHandler.getEntityWhere(EntityProfileData.class, entityProfileMap)).thenReturn(null);

        caEntityKeyGenerationAlgorithm.validate(caEntity);

    }

}
