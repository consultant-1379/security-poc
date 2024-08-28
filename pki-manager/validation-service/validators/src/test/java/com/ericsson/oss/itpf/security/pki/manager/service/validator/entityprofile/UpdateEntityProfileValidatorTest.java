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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile;

import static org.mockito.Mockito.when;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntityProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile.UpdateEntityProfileNameValidator;

@RunWith(MockitoJUnitRunner.class)
public class UpdateEntityProfileValidatorTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(UpdateEntityProfileNameValidator.class);

    @Mock
    private PersistenceManager persistenceManager;

    @InjectMocks
    private UpdateEntityProfileNameValidator updateEntityProfileNameValidator;

    private EntityProfile entityProfile = null;
    private EntityProfileData entityProfileData = null;

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void setUp() throws Exception {

        final EntityProfileSetUpData entityProfileSetUpData = new EntityProfileSetUpData();
        entityProfile = entityProfileSetUpData.getEntityProfile();
        entityProfileData = entityProfileSetUpData.getEntityProfileData();
    }

    /**
     * Method to test updateProfile Method in positive scenario.
     */
    @Test
    public void testUpdateProfile() {

        entityProfileData.setName(entityProfile.getName());
        when(persistenceManager.findEntity(EntityProfileData.class, entityProfile.getId())).thenReturn(entityProfileData);
        when(persistenceManager.findEntityByName(EntityProfileData.class, entityProfile.getName(), EntityProfileSetUpData.NAME_PATH)).thenReturn(null);
        updateEntityProfileNameValidator.validate(entityProfile);
    }

    /**
     * Method to test updateProfile Method in positive scenario.
     */
    @Test(expected = ProfileAlreadyExistsException.class)
    public void testUpdateProfile_AlreadyExists() {
        entityProfile.setName("EP_1");
        when(persistenceManager.findEntity(EntityProfileData.class, entityProfile.getId())).thenReturn(entityProfileData);
        when(persistenceManager.findEntityByName(EntityProfileData.class, entityProfile.getName(), EntityProfileSetUpData.NAME_PATH)).thenReturn(entityProfileData);
        updateEntityProfileNameValidator.validate(entityProfile);
    }

    /**
     * Method to test updateProfile Method in negative scenario.
     */
    @Test(expected = ProfileServiceException.class)
    public void testUpdateProfile_InvalidProfileId() {

        entityProfileData.setName(entityProfile.getName());
        entityProfile.setId(0);
        when(persistenceManager.findEntity(EntityProfileData.class, entityProfile.getId())).thenReturn(null);
        updateEntityProfileNameValidator.validate(entityProfile);
    }

    /**
     * Method to test updateProfile Method in negative scenario.
     */
    @Test(expected = InvalidProfileAttributeException.class)
    public void testUpdateProfile_InvalidProfileName() {
        entityProfile.setName("EntityProfile$1");
        entityProfileData.setName(entityProfile.getName());
        entityProfile.setId(0);
        when(persistenceManager.findEntity(EntityProfileData.class, entityProfile.getId())).thenReturn(null);
        updateEntityProfileNameValidator.validate(entityProfile);
    }

    /**
     * Method to test updateProfile Method in negative scenario.
     */
    @Test(expected = ProfileServiceException.class)
    public void testUpdateProfile_ProfileName() {
        entityProfile.setName("EntityProfile_1");
        entityProfile.setId(0);
        when(persistenceManager.findEntity(EntityProfileData.class, entityProfile.getId())).thenReturn(null);
        updateEntityProfileNameValidator.validate(entityProfile);
    }
}
