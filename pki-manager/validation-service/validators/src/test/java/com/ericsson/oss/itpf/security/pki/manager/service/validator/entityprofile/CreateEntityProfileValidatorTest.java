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

import org.junit.*;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntityProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile.CreateEntityProfileNameValidator;

@RunWith(MockitoJUnitRunner.class)
public class CreateEntityProfileValidatorTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(CreateEntityProfileNameValidator.class);

    @Mock
    private PersistenceManager persistenceManager;

    @InjectMocks
    private CreateEntityProfileNameValidator createEntityProfileNameValidator;

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
     * <<<<<<< Updated upstream Method to test createProfile Method in positive scenario. ======= Method to test positive scenario of creating entity profile. >>>>>>> Stashed changes
     */
    @Test
    public void testCreateProfile() {

        entityProfileData.setName(entityProfile.getName());
        when(persistenceManager.findEntityByName(EntityProfileData.class, entityProfile.getName(), EntityProfileSetUpData.NAME_PATH)).thenReturn(null);
        createEntityProfileNameValidator.validate(entityProfile);
    }
}
