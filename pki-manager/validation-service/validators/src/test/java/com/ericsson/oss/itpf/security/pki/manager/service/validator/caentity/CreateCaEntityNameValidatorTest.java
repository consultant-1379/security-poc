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
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntitiesSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectAltNameValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectValidator;

@SuppressWarnings("unchecked")
@RunWith(MockitoJUnitRunner.class)
public class CreateCaEntityNameValidatorTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(CreateCaEntityNameValidator.class);

    @InjectMocks
    CreateCaEntityNameValidator createCaEntityNameValidator;

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

    private final static String NAME_PATH = "certificateAuthorityData.name";

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
     * Method to test validate method in negative scenario. When providing Invalid name to CertificateAuthority.
     */
    @Test(expected = InvalidEntityAttributeException.class)
    public void testValidateWithInvalidName() {

        caEntity.getCertificateAuthority().setName("ENM RootCA");

        createCaEntityNameValidator.validate(caEntity);

    }

    /**
     * Method to test validate method in negative scenario. When providing Invalid name to CertificateAuthority.
     */
    @Test(expected = InvalidEntityAttributeException.class)
    public void testValidateWithInvalidName1() {

        caEntity.getCertificateAuthority().setName("ENMSu&%bCA");

        createCaEntityNameValidator.validate(caEntity);

    }

    /**
     * Method to test validate method in negative scenario. When providing spaces in name to CertificateAuthority.
     */
    @Test
    public void testValidateWithSpaceInName() {

        caEntity.getCertificateAuthority().setName(" ENMRootCA ");

        createCaEntityNameValidator.validate(caEntity);

        when(persistenceManager.findEntityByName(CAEntityData.class, "ENMSubCA", EntitiesSetUpData.CA_NAME_PATH)).thenReturn(caEntityData);

    }

    /**
     * Method to test validate method in negative scenario. When providing alreaFdy existing CA name.
     */
    @Test(expected = EntityAlreadyExistsException.class)
    public void testValidateWithNameAlreadyExisting() {

        caEntity.getCertificateAuthority().setName("ENMSubCA");

        when(persistenceManager.findEntityByName(CAEntityData.class, "ENMSubCA", EntitiesSetUpData.CA_NAME_PATH)).thenReturn(caEntityData);

        createCaEntityNameValidator.validate(caEntity);

    }

    @Test
    public void testValidateCreate() {

        createCaEntityNameValidator.validate(caEntity);

        verify(persistenceManager, times(1)).findEntityByName(CAEntityData.class, caEntity.getCertificateAuthority().getName(), NAME_PATH);

    }

}
