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
import javax.xml.datatype.DatatypeFactory;

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
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class CertificateValidityValidatorTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateValidityValidator.class);

    @InjectMocks
    CertificateValidityValidator certificateProfileCertificateValidityValidator;

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
     * Method to test validateCertificateValidity in positive scenario.
     */
    @Test
    public void testValidateCertificateValidity() {
        certificateProfileCertificateValidityValidator.validate(certificateProfile);

    }

    /**
     * Method to test validateCertificateValidity With CertificateValidity null.
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateCertificateValidityWithNull() {
        certificateProfile.setCertificateValidity(null);
        certificateProfileCertificateValidityValidator.validate(certificateProfile);
    }

    /**
     * Method to test validateCertificateValidity with Invalid Certificate Validity.
     * 
     * @throws DatatypeConfigurationException
     */
    @Test(expected = InvalidProfileAttributeException.class)
    public void testValidateCertificateValidityInvalid() throws DatatypeConfigurationException {
        certificateProfile.setIssuerUniqueIdentifier(true);
        certificateProfile.setCertificateValidity(DatatypeFactory.newInstance().newDuration(certificateProfileData.getId()));
        certificateProfileCertificateValidityValidator.validate(certificateProfile);
    }

}
