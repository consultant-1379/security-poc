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

import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.util.*;

import javax.persistence.PersistenceException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustCAChain;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.TrustProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.trustprofile.TrustCAChainsValidator;

@RunWith(MockitoJUnitRunner.class)
public class TrustCAChainsValidatorTest {

    @Mock
    private Logger logger;

    @InjectMocks
    private TrustCAChainsValidator trustCAChainsValidator;

    @Mock
    private PersistenceManager persistenceManager;

    private Set<String> caEntitiesNames;
    private List<TrustCAChain> trustCAChains;
    private List<TrustCAChain> invalidTrustCAChains;
    private List<CAEntityData> internalCAsList;
    private TrustProfile trustProfile;

    /**
     * Method to fill the data into CAEntity
     */
    @Before
    public void setup() {
        final TrustProfileSetUpData trustProfileSetUpData = new TrustProfileSetUpData();
        trustProfile = trustProfileSetUpData.getTrustProfile();
        caEntitiesNames = trustProfileSetUpData.getInternalCANames();
        internalCAsList = trustProfileSetUpData.getInternalCaEntityDatas();
        trustCAChains = trustProfileSetUpData.getTrustCAChains();

        invalidTrustCAChains = new ArrayList<TrustCAChain>();
        final TrustCAChain invalidTrustCAChain = new TrustCAChain();
        invalidTrustCAChain.setInternalCA(null);
        invalidTrustCAChains.add(invalidTrustCAChain);
    }

    /**
     * Method to test validateCAs in negative scenario
     */
    @Test(expected = InvalidProfileAttributeException.class)
    public void testValidatesCAsEmpty() {
        final TrustCAChain invalidTrustCAChain = new TrustCAChain();
        List<TrustCAChain> trustCAChains = new ArrayList<TrustCAChain>();
        trustCAChains.add(invalidTrustCAChain);
        trustProfile.setTrustCAChains(trustCAChains);
        trustCAChainsValidator.validate(trustProfile);
    }

    /**
     * Method to test validateCAs in positive scenario
     */
    @Test
    public void testValidateCAs() {

        when(persistenceManager.findEntityIN(CAEntityData.class, caEntitiesNames, TrustProfileSetUpData.NAME_PATH_IN_CA)).thenReturn(internalCAsList);
        trustCAChainsValidator.validate(trustProfile);
        verify(logger).debug("Validating Internal CAs {}", trustCAChains);

    }

    /**
     * Method to test validateCAs in negative scenario
     */
    @Test(expected = CANotFoundException.class)
    public void testValidateCAsNotFound() {

        caEntitiesNames.add("Internal CA 3");
        when(persistenceManager.findEntityIN(CAEntityData.class, caEntitiesNames, TrustProfileSetUpData.NAME_PATH_IN_CA)).thenReturn(internalCAsList);
        trustCAChainsValidator.validate(trustProfile);

    }

    /**
     * Method to test validateCAs in negative scenario
     */
    @Test(expected = ProfileServiceException.class)
    public void testValidateCAsPersistenceException() {

        when(persistenceManager.findEntityIN(CAEntityData.class, caEntitiesNames, TrustProfileSetUpData.NAME_PATH_IN_CA)).thenThrow(new PersistenceException());
        trustCAChainsValidator.validate(trustProfile);

    }

    @Test(expected = InvalidProfileAttributeException.class)
    public void testValidateWithInvalidCAs() {
        trustProfile.setTrustCAChains(invalidTrustCAChains);
        trustCAChainsValidator.validate(trustProfile);
    }

    @Test(expected = InvalidProfileAttributeException.class)
    public void testValidateWithInvalidCAs2() {

        invalidTrustCAChains.get(0).setInternalCA(new CAEntity());
        trustProfile.setTrustCAChains(invalidTrustCAChains);
        trustCAChainsValidator.validate(trustProfile);

    }

    @Test(expected = InvalidProfileAttributeException.class)
    public void testValidateWithDuplicateCAs() {

        trustCAChains.add(trustCAChains.get(0));
        trustCAChainsValidator.validate(trustProfile);

    }

    @Test
    public void testValidateWithNullCAs() {

        trustProfile.setTrustCAChains(null);
        trustCAChainsValidator.validate(trustProfile);

    }

    /**
     * Method to test validate()
     */
    @Test
    public void testValidate() {

        trustCAChainsValidator.validate(new TrustProfile());

        verify(logger).debug("Trust Profile must contain atleast one internal CA");

    }

}
