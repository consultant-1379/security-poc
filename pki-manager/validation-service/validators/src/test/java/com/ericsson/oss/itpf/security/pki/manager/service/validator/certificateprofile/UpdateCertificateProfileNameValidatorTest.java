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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateprofile;

import static org.mockito.Mockito.when;

import javax.persistence.PersistenceException;
import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.constants.Constants;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class UpdateCertificateProfileNameValidatorTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(UpdateCertificateProfileNameValidator.class);

    @InjectMocks
    UpdateCertificateProfileNameValidator updateCertificateProfileNameValidator;

    @Mock
    PersistenceManager persistenceManager;

    private CertificateProfile certificateProfile;
    private CertificateProfileData certificateProfileData;

    /**
     * Method to provide dummy data for tests.
     *
     * @throws DatatypeConfigurationException
     */
    @Before
    public void fillData() throws DatatypeConfigurationException {
        final CertificateProfileSetUpData certificateProfileSetUpToTest = new CertificateProfileSetUpData();
        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        certificateProfileData = certificateProfileSetUpToTest.getCertificateProfileData();

    }

    /**
     * Method to test validateCertificateProfileName method in positive scenario.
     */
    @Test
    public void testValidateCertificateProfileName() {
        when(persistenceManager.findEntity(CertificateProfileData.class, certificateProfile.getId())).thenReturn(certificateProfileData);
        updateCertificateProfileNameValidator.validate(certificateProfile);
    }


    /**
     * Method to test validateCertificateProfileName with given profile already exists.
     */
    @Test(expected = ProfileAlreadyExistsException.class)
    public void testValidateCertificateProfileNameForUpdate() {
        certificateProfileData.setName("TTestCP");
        when(persistenceManager.findEntityByName(CertificateProfileData.class, certificateProfile.getName(), Constants.NAME_PATH) == null).thenReturn(false);
        updateCertificateProfileNameValidator.checkProfileNameForUpdate(certificateProfile.getName(), certificateProfileData.getName(), CertificateProfileData.class);

    }

    /**
     * Method to test validateCertificateProfileName in negative scenario, While finding the entity in database.
     */
    @Test(expected = ProfileServiceException.class)
    public void testValidateCertificateProfileNameForDBErrors() {
        when(persistenceManager.findEntity(CertificateProfileData.class, certificateProfile.getId())).thenThrow(new PersistenceException());
        updateCertificateProfileNameValidator.validate(certificateProfile);
    }


}
