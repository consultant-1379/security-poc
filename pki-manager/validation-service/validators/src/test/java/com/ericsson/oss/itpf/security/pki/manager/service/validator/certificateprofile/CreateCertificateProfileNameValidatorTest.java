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

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration.AlgorithmPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateprofile.CreateCertificateProfileNameValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.constants.Constants;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.AbstractProfileNameValidator;

@RunWith(MockitoJUnitRunner.class)
public class CreateCertificateProfileNameValidatorTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(CreateCertificateProfileNameValidator.class);

    @Spy
    final Logger logger1 = LoggerFactory.getLogger(AbstractProfileNameValidator.class);

    @InjectMocks
    CreateCertificateProfileNameValidator createCertificateProfileNameValidator;

    @Mock
    AlgorithmPersistenceHandler algorithmPersistenceHandler;

    @Mock
    private PersistenceManager persistenceManager;

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
     * Method to test validateCertificateProfileName in positive scenario.
     */
    @Test
    public void testValidateCertificateProfileName() {
        createCertificateProfileNameValidator.validate(certificateProfile);

    }

    /**
     * Method to test validateCertificateProfileName method in negative scenario, When ProfileName is Empty string.
     */
    @Test(expected = InvalidProfileAttributeException.class)
    public void testValidateProfileNameWithEmpty() {
        certificateProfile.setName("");
        createCertificateProfileNameValidator.validate(certificateProfile);
    }

    /**
     * Method to test validateCertificateProfileName in negative scenario, with Invalid Profile Name.
     */
    @Test(expected = InvalidProfileAttributeException.class)
    public void testValidateProfileNameInvalid() {
        certificateProfile.setName("**90099032__$$5@#@");
        createCertificateProfileNameValidator.validate(certificateProfile);
    }

    /**
     * Method to test validateCertificateProfileName with already existing Profile Name.
     */
    @Test(expected = ProfileAlreadyExistsException.class)
    public void testValidateProfileNameAvailability() {
        when(persistenceManager.findEntityByName(CertificateProfileData.class, certificateProfile.getName(), Constants.NAME_PATH) == null).thenReturn(false);
        createCertificateProfileNameValidator.checkProfileNameAvailability(certificateProfile.getName(), CertificateProfileData.class);
    }

}
