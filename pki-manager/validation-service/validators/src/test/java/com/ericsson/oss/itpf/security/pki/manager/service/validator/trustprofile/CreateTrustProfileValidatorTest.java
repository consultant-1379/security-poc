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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.trustprofile;

import static org.junit.Assert.*;
import static org.mockito.Mockito.times;
import static org.mockito.Mockito.when;

import javax.persistence.PersistenceException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.TrustProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.TrustProfileSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class CreateTrustProfileValidatorTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(CreateTrustProfileValidatorTest.class);

    @InjectMocks
    private CreateTrustProfileNameValidator createTrustProfileNameValidator;

    @Mock
    private PersistenceManager persistenceManager;

    private TrustProfile trustProfile;

    private String name;
    private long id;

    @Before
    public void setup() {

        final TrustProfileSetUpData trustProfileSetUpData = new TrustProfileSetUpData();

        trustProfile = trustProfileSetUpData.getTrustProfile();

        name = trustProfile.getName();
        id = trustProfile.getId();

    }

    @Test
    public void testValidateCreate_TrustProfile() {

        when(persistenceManager.findEntityByName(TrustProfileData.class, name, TrustProfileSetUpData.NAME_PATH)).thenReturn(null);
        createTrustProfileNameValidator.validate(trustProfile);
    }

    @Test(expected = InvalidProfileAttributeException.class)
    public void testValidateCreateInvalidName() {

        trustProfile.setName("TestProfile@#");
        when(persistenceManager.findEntityByName(TrustProfileData.class, "TestProfile@#", TrustProfileSetUpData.NAME_PATH)).thenReturn(null);
        createTrustProfileNameValidator.validate(trustProfile);
        assertTrue(trustProfile.getTrustCAChains().isEmpty());
    }

    @Test(expected = ProfileAlreadyExistsException.class)
    public void testValidateCreateThrowsProfileAlreadyExistsException() {

        when(persistenceManager.findEntityByName(TrustProfileData.class, name, TrustProfileSetUpData.NAME_PATH)).thenReturn(new TrustProfileData());

        createTrustProfileNameValidator.validate(trustProfile);
        Mockito.verify(persistenceManager, times(1)).findEntityByName(TrustProfileData.class, name, TrustProfileSetUpData.NAME_PATH);
    }

    @Test(expected = ProfileServiceException.class)
    public void testValidateCreateThrowsProfileServiceException() {

        when(persistenceManager.findEntityByName(TrustProfileData.class, name, TrustProfileSetUpData.NAME_PATH)).thenThrow(new PersistenceException());

        createTrustProfileNameValidator.validate(trustProfile);
        assertTrue(ValidationUtils.validatePattern("^[a-zA-Z0-9_ -]{3,255}$", trustProfile.getName()));
    }

    @Test
    public void testGetEntityData_ProfileDataClass_EntityData() {

        when(persistenceManager.findEntity(TrustProfileData.class, id)).thenReturn(new TrustProfileData());

        assertNotNull(createTrustProfileNameValidator.getEntityData(id, TrustProfileData.class));

    }

    @Test(expected = ProfileNotFoundException.class)
    public void testGetEntityDataThrowsProfileNotFoundException() {

        when(persistenceManager.findEntity(TrustProfileData.class, id)).thenReturn(null);

        assertNull(createTrustProfileNameValidator.getEntityData(id, TrustProfileData.class));
    }

    @Test
    public void testIsNameAvailable_profileName_Boolean() {

        when(persistenceManager.findEntityByName(TrustProfileData.class, name, TrustProfileSetUpData.NAME_PATH)).thenReturn(null);

        assertTrue(createTrustProfileNameValidator.isNameAvailable(name, TrustProfileData.class));

    }

    @Test
    public void testIsNameAvailableReturnFalse() {

        when(persistenceManager.findEntityByName(TrustProfileData.class, name, TrustProfileSetUpData.NAME_PATH)).thenReturn(new TrustProfileData());

        assertFalse(createTrustProfileNameValidator.isNameAvailable(name, TrustProfileData.class));

    }

    @Test(expected = ProfileServiceException.class)
    public void testIsNameAvailableThrowsProfileServiceException() {

        when(persistenceManager.findEntityByName(TrustProfileData.class, name, TrustProfileSetUpData.NAME_PATH)).thenThrow(new PersistenceException());

        assertTrue(createTrustProfileNameValidator.isNameAvailable(name, TrustProfileData.class));

    }

    @Test
    public void testCheckProfileNameForUpdate_TrustProfileSetUpData() {

        when(persistenceManager.findEntityByName(TrustProfileData.class, name, TrustProfileSetUpData.NAME_PATH)).thenReturn(null);

        createTrustProfileNameValidator.checkProfileNameForUpdate(name, TrustProfileSetUpData.NAME_PATH, TrustProfileData.class);

        Mockito.verify(persistenceManager, times(1)).findEntityByName(TrustProfileData.class, name, TrustProfileSetUpData.NAME_PATH);

    }

}
