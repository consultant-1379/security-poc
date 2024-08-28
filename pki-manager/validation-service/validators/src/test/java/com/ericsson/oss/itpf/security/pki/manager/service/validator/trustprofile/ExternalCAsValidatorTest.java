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

import static org.mockito.Mockito.times;

import java.util.ArrayList;
import java.util.List;

import javax.persistence.PersistenceException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.ExternalCredentialMgmtServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.TrustProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.trustprofile.ExternalCAsValidator;

/**
 * Class to test ExternalCAsValidator
 */
@RunWith(MockitoJUnitRunner.class)
public class ExternalCAsValidatorTest {

    @InjectMocks
    ExternalCAsValidator externalCAsValidator;

    @Mock
    Logger logger;

    @Mock
    PersistenceManager persistenceManager;

    private TrustProfile trustProfile;
    private final static String NAME_PATH_IN_CA = "certificateAuthorityData.name";
    private List<String> externalCANames;
    private List<CAEntityData> caEntityDataList;
    private TrustProfileSetUpData trustProfileSetUpData;

    /**
     * @throws java.lang.Exception
     */
    @Before
    public void setUp() throws Exception {

        trustProfileSetUpData = new TrustProfileSetUpData();
        trustProfile = trustProfileSetUpData.getTrustProfile();

        caEntityDataList = new ArrayList<CAEntityData>();
        caEntityDataList.add(createExternalCA());

        externalCANames = new ArrayList<String>();
        externalCANames.add("External CA 1");
    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.service.validator.trustprofile.ExternalCAsValidator#validate(com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile)}.
     */
    @Test
    public void testValidate() {

        externalCAsValidator.validate(new TrustProfile());

        Mockito.verify(logger, times(1)).debug("Trust Profile doesn't contain external CA");

    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.service.validator.trustprofile.ExternalCAsValidator#validate(com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile)}.
     */
    @Test(expected = CANotFoundException.class)
    public void testValidateThrowsCANotFoundException() {

        externalCAsValidator.validate(trustProfile);

    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.service.validator.trustprofile.ExternalCAsValidator#validate(com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile)}.
     */
    @Test(expected = ExternalCredentialMgmtServiceException.class)
    public void testValidateThrowsExternalCredentialMgmtServiceException() {

        Mockito.when(persistenceManager.findEntityIN(CAEntityData.class, externalCANames, NAME_PATH_IN_CA)).thenThrow(new PersistenceException());

        externalCAsValidator.validate(trustProfile);

    }

    /**
     * Test method for
     * {@link com.ericsson.oss.itpf.security.pki.manager.service.validator.trustprofile.ExternalCAsValidator#validate(com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile)}.
     */
    @Test
    public void testValidateThrows() {

        Mockito.when(persistenceManager.findEntityIN(CAEntityData.class, externalCANames, NAME_PATH_IN_CA)).thenReturn(caEntityDataList);

        externalCAsValidator.validate(trustProfile);

        Mockito.verify(persistenceManager, times(1)).findEntityIN(CAEntityData.class, externalCANames, NAME_PATH_IN_CA);
    }

    /**
     * Method to prepare CAEntityData
     */
    private CAEntityData createExternalCA() {

        final CAEntityData externalCA = new CAEntityData();
        final CertificateAuthorityData certificateAuthorityData = new CertificateAuthorityData();

        externalCA.setId(1);
        certificateAuthorityData.setName("External CA 1");
        externalCA.setCertificateAuthorityData(certificateAuthorityData);
        externalCA.setExternalCA(true);

        return externalCA;
    }

}
