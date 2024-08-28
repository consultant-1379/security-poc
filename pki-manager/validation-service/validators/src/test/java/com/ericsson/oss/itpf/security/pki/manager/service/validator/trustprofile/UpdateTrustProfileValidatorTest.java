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
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.TrustProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.TrustProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ItemType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ValidateItem;

@RunWith(MockitoJUnitRunner.class)
public class UpdateTrustProfileValidatorTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(UpdateTrustProfileValidatorTest.class);

    @InjectMocks
    private UpdateTrustProfileNameValidator updateTrustProfileNameValidator;

    @Mock
    private TrustCAChainsValidator trustCAChainsValidator;

    @Mock
    private ExternalCAsValidator externalCAsValidator;

    @Mock
    private PersistenceManager persistenceManager;

    private TrustProfile trustProfile;

    private TrustProfileData trustProfileData;

    private ValidateItem validateItem;

    private long id;

    /**
     * Method to fill test data into TrustProfile and TrustProfileData
     */
    @Before
    public void setup() {

        final TrustProfileSetUpData trustProfileSetUpData = new TrustProfileSetUpData();
        validateItem = new ValidateItem();

        trustProfileData = trustProfileSetUpData.getTrustProfileData();

        trustProfile = trustProfileSetUpData.getTrustProfile();

        id = trustProfile.getId();

        validateItem.setItem(trustProfile);
        validateItem.setItemType(ItemType.TRUST_PROFILE);
        validateItem.setOperationType(com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.OperationType.UPDATE);

    }

    /**
     * Method to test validateUpdate in positive scenario
     */
    @Test
    public void testValidateUpdate() {
        when(persistenceManager.findEntity(TrustProfileData.class, id)).thenReturn(trustProfileData);
        updateTrustProfileNameValidator.validate(trustProfile);
    }

    /**
     * Method to test validateUpdate in negative scenario
     */
    @Test(expected = ProfileAlreadyExistsException.class)
    public void testValidateUpdateName() {
        trustProfile.setName("TestProfileUpdate");
        when(persistenceManager.findEntity(TrustProfileData.class, id)).thenReturn(trustProfileData);
        when(persistenceManager.findEntityByName(TrustProfileData.class, "TestProfileUpdate", TrustProfileSetUpData.NAME_PATH)).thenReturn(trustProfileData);
        updateTrustProfileNameValidator.validate(trustProfile);
    }

    /**
     * Method to test validateUpdate in negative scenario
     */
    @Test(expected = InvalidProfileAttributeException.class)
    public void testValidateUpdateNameEmpty() {
        trustProfile.setName("");
        when(persistenceManager.findEntity(TrustProfileData.class, id)).thenReturn(trustProfileData);
        when(persistenceManager.findEntityByName(TrustProfileData.class, "TestProfileUpdate", TrustProfileSetUpData.NAME_PATH)).thenReturn(trustProfileData);
        updateTrustProfileNameValidator.validate(trustProfile);
    }

    /**
     * Method to test validateUpdate in negative scenario
     */
    @Test(expected = ProfileServiceException.class)
    public void testValidateUpdateNamePersistenceException() {
        trustProfile.setName("TestProfileUpdate");
        when(persistenceManager.findEntity(TrustProfileData.class, id)).thenReturn(trustProfileData);
        when(persistenceManager.findEntityByName(TrustProfileData.class, "TestProfileUpdate", TrustProfileSetUpData.NAME_PATH)).thenThrow(new PersistenceException());
        updateTrustProfileNameValidator.validate(trustProfile);
    }

    /**
     * Method to test validateUpdate in negative scenario
     */
    @Test(expected = ProfileNotFoundException.class)
    public void testValidateUpdateNoProfile() {
        when(persistenceManager.findEntity(TrustProfileData.class, id)).thenReturn(null);
        updateTrustProfileNameValidator.validate(trustProfile);
    }

    /**
     * Method to test validate in positive scenario
     */
    /*
     * @Test public void testValidateUpdateOperation() { when(persistenceManager.findEntity(TrustProfileData.class, id)).thenReturn(trustProfileData);
     * updateTrustProfileNameValidator.validate(trustProfile, OperationType.UPDATE); verify(persistenceManager).findEntity(TrustProfileData.class, id); }
     */
}
