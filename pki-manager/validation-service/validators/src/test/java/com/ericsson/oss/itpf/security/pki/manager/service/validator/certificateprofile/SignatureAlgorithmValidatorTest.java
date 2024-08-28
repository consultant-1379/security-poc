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

import static org.mockito.Mockito.doThrow;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration.AlgorithmPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.AlgorithmException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateprofile.CertificateProfileSignatureAlgorithmValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.configuration.SignatureAlgorithmValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class SignatureAlgorithmValidatorTest {
    @Spy
    final Logger logger = LoggerFactory.getLogger(CertificateProfileSignatureAlgorithmValidator.class);
    @Spy
    final Logger logger1 = LoggerFactory.getLogger(SignatureAlgorithmValidator.class);

    @InjectMocks
    CertificateProfileSignatureAlgorithmValidator certificateProfileSignatureAlgorithmValidator;

    @Mock
    SignatureAlgorithmValidator signatureAlgorithmValidator;

    @Mock
    AlgorithmPersistenceHandler algorithmPersistenceHandler;

    @Mock
    private PersistenceManager persistenceManager;

    private CertificateProfile certificateProfile;
    private CertificateProfileData certificateProfileData;
    private Algorithm signatureAlgorithm;
    private AlgorithmData algorithmData;

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
     * Method to test validateSignatureAlgorithm in negative scenario, when Signature Algorithm is null.
     */
    @Test(expected = AlgorithmException.class)
    public void testValidateSignatureAlgorithmWithNull() {
        certificateProfile.setSignatureAlgorithm(null);
        doThrow(new AlgorithmException()).when(signatureAlgorithmValidator).validate(signatureAlgorithm);
        certificateProfileSignatureAlgorithmValidator.validate(certificateProfile);
    }

    /**
     * Method to test validateSignatureAlgorithm in positive scenario.
     */
    @Test
    public void testValidateSignatureAlgorithm() {
        certificateProfileSignatureAlgorithmValidator.validate(certificateProfile);
    }

    /**
     * Method to test validateSignatureAlgorithm in negative scenario, when Signature Algorithm Data is null.
     */
    @Test(expected = AlgorithmNotFoundException.class)
    public void testValidateSignatureAlgorithmWithNullAlgorithmData() {
        signatureAlgorithm = certificateProfile.getSignatureAlgorithm();
        doThrow(new AlgorithmNotFoundException()).when(signatureAlgorithmValidator).validate(signatureAlgorithm);
        certificateProfileSignatureAlgorithmValidator.validate(certificateProfile);
    }

}
