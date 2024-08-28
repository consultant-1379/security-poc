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

import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectValidator;

@RunWith(MockitoJUnitRunner.class)
public class SubjectCapabilitiesValidatorTest {
    @Spy
    final Logger logger = LoggerFactory.getLogger(SubjectCapabilitiesValidator.class);

    @InjectMocks
    SubjectCapabilitiesValidator subjectCapabilitiesValidator;

    @Mock
    SubjectField subjectField;

    @Mock
    SubjectValidator subjectValidator;

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
     * Method to test validateSubjectCapabilities in negative scenario, when SubjectCapabilties null.
     */
    @Test(expected = InvalidSubjectException.class)
    public void testValidateSubjectCapabilitiesWithNullsubjectCapabilities() {
        certificateProfile.setSubjectCapabilities(null);
        subjectCapabilitiesValidator.validate(certificateProfile);
    }

    /**
     * Method to test validateSubjectCapabilities in negative scenario, when SubjectFields null.
     */
    @Test(expected = InvalidSubjectException.class)
    public void testValidateSubjectCapabilitiesWithNullSubjectFields() {
        certificateProfile.getSubjectCapabilities().setSubjectFields(null);
        subjectCapabilitiesValidator.validate(certificateProfile);
    }

    /**
     * Method to test validateSubjectCapabilities in negative scenario, when SubjectFieldType null.
     */
    @Test(expected = MissingMandatoryFieldException.class)
    public void testValidateSubjectCapabilitiesWithNullSubjectFieldType() {
        final List<SubjectField> subjectFields = certificateProfile.getSubjectCapabilities().getSubjectFields();
        for (final SubjectField subjectField : subjectFields) {
            subjectField.setType(null);
        }
        subjectCapabilitiesValidator.validate(certificateProfile);
    }

    /**
     * Method to test validateSubjectCapabilities in negative scenario, when SubjectFieldValue null.
     */
    @Test(expected = InvalidSubjectException.class)
    public void testvalidateSubjectCapabilitiesWithNotNullSubjectFieldValue() {
        final List<SubjectField> subjectFields = certificateProfile.getSubjectCapabilities().getSubjectFields();
        for (final SubjectField subjectField : subjectFields) {
            subjectField.setValue("TestValue");
        }
        subjectCapabilitiesValidator.validate(certificateProfile);
    }

    /**
     * Method to test validateSubjectCapabilities in Positive scenario.
     */
    @Test
    public void testValidateSubjectCapabilities() {
        subjectCapabilitiesValidator.validate(certificateProfile);
    }
}
