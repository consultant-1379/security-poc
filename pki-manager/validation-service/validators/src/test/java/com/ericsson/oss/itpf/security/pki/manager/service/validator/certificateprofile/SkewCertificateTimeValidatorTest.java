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

import static org.mockito.Mockito.verify;

import javax.xml.datatype.DatatypeConfigurationException;
import javax.xml.datatype.DatatypeFactory;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class SkewCertificateTimeValidatorTest {

    @Mock
    Logger logger;

    @InjectMocks
    SkewCertificateTimeValidator skewCertificateTimeValidator;

    private CertificateProfile certificateProfile;
    private CertificateProfileData certificateProfileData;
    private CAEntityData caEntityData;

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
     * Method to test validateSkewCertificateTime in positive scenario.
     */
    @Test
    public void testValidateSkewCertificateTime() {
        skewCertificateTimeValidator.validate(certificateProfile);
    }
    
    /**
     * Method to test validateSkewCertificateTime with Zero duration in positive scenario.
     * 
     * @throws DatatypeConfigurationException 
     */
    @Test
    public void testValidateSkewCertificateTimeWithZeroDuration() throws DatatypeConfigurationException {
        certificateProfile.setSkewCertificateTime(DatatypeFactory.newInstance().newDuration("P0Y0M0DT0H0M0S"));
        skewCertificateTimeValidator.validate(certificateProfile);
    }

    /**
     * Method to test validateCreate method in negative scenario. When skew time is given as invalid value.
     *
     * @throws DatatypeConfigurationException
     */
    @Test(expected = InvalidProfileAttributeException.class)
    public void testValidateCertificateSkewTimeInvalid() throws DatatypeConfigurationException {
        certificateProfile.setIssuerUniqueIdentifier(true);
        certificateProfile.setSkewCertificateTime(DatatypeFactory.newInstance().newDuration(certificateProfileData.getId()));
        skewCertificateTimeValidator.validate(certificateProfile);
    }

    /**
     * Method to test validateSkewCertificateTime in negative scenario. When skew certificate time value is null.
     */
    @Test
    public void testValidateSkewCertificateTimeAsnull() {
        certificateProfile.setSkewCertificateTime(null);
        skewCertificateTimeValidator.validate(certificateProfile);
        verify(logger).debug("Validating SkewCertificateTime in CertificateProfile {} ", certificateProfile.getSkewCertificateTime());
    }

    /**
     * Method to test validateSkewCertificateTime in negative scenario.
     */
    @Test(expected = InvalidProfileAttributeException.class)
    public void testValidateSkewCertificateTimeValueLonger() throws DatatypeConfigurationException {
        certificateProfile.setSkewCertificateTime(DatatypeFactory.newInstance().newDuration(2l));
        certificateProfile.setCertificateValidity(DatatypeFactory.newInstance().newDuration(1l));
        skewCertificateTimeValidator.validate(certificateProfile);
    }
}
