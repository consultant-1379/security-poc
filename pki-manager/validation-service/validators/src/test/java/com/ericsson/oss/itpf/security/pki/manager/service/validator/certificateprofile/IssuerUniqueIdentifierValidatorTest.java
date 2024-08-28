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

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateprofile.IssuerUniqueIdentifierValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class IssuerUniqueIdentifierValidatorTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(IssuerUniqueIdentifierValidator.class);

    @InjectMocks
    IssuerUniqueIdentifierValidator issuerUniqueIdentifierValidator;

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
     * Method to test validateIssuerUniqueIdentifier method in positive scenario.
     */
    @Test
    public void testValidateIssuerUniqueIdentifier() {
        issuerUniqueIdentifierValidator.validate(certificateProfile);

    }

    /**
     * Method to test validateIssuerUniqueIdentifier method in negative scenario, When Issuer Unique Identifier is true.
     */
    @Test(expected = InvalidProfileAttributeException.class)
    public void testisFieldAvailableForProfileV3() {
        certificateProfile.setIssuerUniqueIdentifier(true);
        issuerUniqueIdentifierValidator.validate(certificateProfile);

    }
}
