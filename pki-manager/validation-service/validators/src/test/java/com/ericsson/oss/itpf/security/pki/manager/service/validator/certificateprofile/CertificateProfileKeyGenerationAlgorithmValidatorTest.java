/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
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

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.configuration.KeyGenerationAlgorithmsValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class CertificateProfileKeyGenerationAlgorithmValidatorTest {

    @Mock
    Logger logger;
    @InjectMocks
    CertificateProfileKeyGenerationAlgorithmValidator certificateProfileKeyGenerationAlgorithmValidator;
    @Mock
    KeyGenerationAlgorithmsValidator keyGenerationAlgorithmValidators;
    private CertificateProfile certificateProfile;

    /**
     * Method to provide dummy data for tests.
     *
     * @throws DatatypeConfigurationException
     */
    @Before
    public void fillData() throws DatatypeConfigurationException {
        final CertificateProfileSetUpData certificateProfileSetUpToTest = new CertificateProfileSetUpData();
        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
    }

    /**
     * This Method tests validateCAIssuer in Positive scenario.
     */
    @Test
    public void testValidateCAIssuerWithNullIssuerName() {
        certificateProfileKeyGenerationAlgorithmValidator.validate(certificateProfile);
        verify(logger).debug("Validating KeyGenerationAlgorithmList in Certificate Profile {} ", certificateProfile.getKeyGenerationAlgorithms());

    }

}
