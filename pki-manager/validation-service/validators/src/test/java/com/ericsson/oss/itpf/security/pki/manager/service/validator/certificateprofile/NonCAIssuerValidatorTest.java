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
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateprofile.NonCAIssuerValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class NonCAIssuerValidatorTest {
    @Spy
    final Logger logger = LoggerFactory.getLogger(NonCAIssuerValidator.class);

    @InjectMocks
    NonCAIssuerValidator nonCAIssuerValidator;

    @Mock
    private PersistenceManager persistenceManager;

    private CertificateProfile certificateProfile;
    private CertificateProfileData certificateProfileData;
    private CAEntityData caEntityData;
    private final static String CA_NAME_PATH = "certificateAuthorityData.name";

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
        caEntityData = certificateProfileData.getIssuerData();
    }

    /**
     * Method to test validateIssuerNameForNonCA with null issuer.
     * 
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateIssuerNameForNonCA() {
        certificateProfile.setIssuer(null);
        nonCAIssuerValidator.validate(certificateProfile);

    }

    /**
     * Method to test validateIssuerNameForNonCA with null CertificateAuthority Name.
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateIssuerNameForNonCAWithCANameNull() {
        final CAEntity issuer = certificateProfile.getIssuer();
        issuer.getCertificateAuthority().setName(null);
        nonCAIssuerValidator.validate(certificateProfile);
    }

    /**
     * Method to test ValidateIssuerNameForNonCA with null CAEntityData.
     */
    @Test(expected = CANotFoundException.class)
    public void testValidateIssuerNameForNonCAWithNullCAEntityData() {
        final String issuerName = certificateProfile.getIssuer().getCertificateAuthority().getName();
        when(persistenceManager.findEntityByName(CAEntityData.class, issuerName, CA_NAME_PATH)).thenReturn(null);
        nonCAIssuerValidator.validate(certificateProfile);
    }

    /**
     * Method to test validateIssuerName in negative scenario, when CAEntity is ExternalCA.
     */
    @Test(expected = CANotFoundException.class)
    public void testValidateIssuerNameForNonCAWithExternalCA() {
        final String issuerName = certificateProfile.getIssuer().getCertificateAuthority().getName();
        when(persistenceManager.findEntityByName(CAEntityData.class, issuerName, CA_NAME_PATH)).thenReturn(caEntityData);
        caEntityData.setExternalCA(true);
        nonCAIssuerValidator.validate(certificateProfile);
    }

    /**
     * Method to test validateIssuerName in negative scenario, when fetching entity from DB.
     */
    @Test(expected = ProfileServiceException.class)
    public void testValidateIssuerNameForNonCAWithDBErrors() {
        final CAEntity issuer = certificateProfile.getIssuer();
        final String issuerName = issuer.getCertificateAuthority().getName();
        when(persistenceManager.findEntityByName(CAEntityData.class, issuerName, CA_NAME_PATH)).thenThrow(new PersistenceException());
        nonCAIssuerValidator.validate(certificateProfile);
    }

    /**
     * Method to test validateIssuerName in positive scenario.
     */
    @Test
    public void testvalidateIssuerName() {
        final String issuerName = certificateProfile.getIssuer().getCertificateAuthority().getName();
        when(persistenceManager.findEntityByName(CAEntityData.class, issuerName, CA_NAME_PATH)).thenReturn(caEntityData);
        nonCAIssuerValidator.validate(certificateProfile);
    }

}
