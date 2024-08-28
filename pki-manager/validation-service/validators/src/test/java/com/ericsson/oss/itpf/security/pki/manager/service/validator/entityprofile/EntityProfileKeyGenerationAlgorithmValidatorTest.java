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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.entityprofile;

import static org.mockito.Mockito.when;

import java.io.FileNotFoundException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.ProfilePersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration.AlgorithmPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.TrustProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.configuration.KeyGenerationAlgorithmValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.CertificateProfileSetUpData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntityProfileSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class EntityProfileKeyGenerationAlgorithmValidatorTest {

    @Spy
    final Logger logger = LoggerFactory.getLogger(EPKeyGenerationAlgorithmValidator.class);

    @Spy
    final Logger logger1 = LoggerFactory.getLogger(KeyGenerationAlgorithmValidator.class);

    @InjectMocks
    EPKeyGenerationAlgorithmValidator entityProfileKeyGenerationAlgorithmValidator;

    @Mock
    ProfilePersistenceHandlerFactory persistenceHandlerFactory;

    @Mock
    AlgorithmPersistenceHandler algorithmPersistenceHandler;

    @Mock
    KeyGenerationAlgorithmValidator keyGenerationAlgorithmValidator;

    private EntityProfile entityProfile = null;
    private CertificateProfile certificateProfile = null;
    private EntityProfileSetUpData entityProfileSetUpToTest;

    /**
     * Method to provide dummy data for tests.
     */
    @Before
    public void setUp() throws Exception {
        entityProfileSetUpToTest = new EntityProfileSetUpData();
        CertificateProfileSetUpData certificateProfileSetUpToTest = new CertificateProfileSetUpData();
        entityProfile = entityProfileSetUpToTest.getEntityProfile();
        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        CertificateProfileData certificateProfileData = certificateProfileSetUpToTest.getCertificateProfileData();

        certificateProfile.setCertificateExtensions(certificateProfileSetUpToTest.getCertificateProfile().getCertificateExtensions());
        certificateProfileData.setCertificateExtensionsJSONData(JsonUtil.getJsonFromObject(certificateProfileSetUpToTest.getCertificateProfile().getCertificateExtensions()));
        TrustProfileData trustProfileData = new TrustProfileData();
        trustProfileData.setName("TrustProfile_1");
    }

    /**
     * Method to test ValidateCreate method in positive scenario.
     */
    @Test
    public void testCreateProfile_ValidAlgorithm() throws FileNotFoundException {

        final EntityProfile entityProfile_dummy = entityProfile;
        final AlgorithmData algorithmData = entityProfileSetUpToTest.getAlgorithmData();
        final TrustProfile trustProfile = new TrustProfile();
        trustProfile.setName("TrustProfile_1");

        final CertificateProfile certProfile = new CertificateProfile();
        certProfile.setName("CertificateProfile_1");

        final Algorithm algorithm = new Algorithm();
        algorithm.setName("RSA");
        algorithm.setKeySize(2048);
        algorithm.setSupported(true);
        entityProfile_dummy.setKeyGenerationAlgorithm(algorithm);
        when(algorithmPersistenceHandler.getAlgorithmByNameAndType(entityProfile.getKeyGenerationAlgorithm(), AlgorithmType.ASYMMETRIC_KEY_ALGORITHM)).thenReturn(algorithmData);

        entityProfileKeyGenerationAlgorithmValidator.validate(entityProfile);

    }

    /**
     * Method to test ValidateCreate method in positive scenario.
     */
    @Test
    public void testCreateProfile_InValidAlgorithm() throws FileNotFoundException {

        final EntityProfile entityProfile_dummy = entityProfile;
        final AlgorithmData algorithmData = entityProfileSetUpToTest.getAlgorithmData();
        final TrustProfile trustProfile = new TrustProfile();
        trustProfile.setName("TrustProfile_1");

        final CertificateProfile certProfile = new CertificateProfile();
        certProfile.setName("CertificateProfile_1");

        final Algorithm algorithm = null;
        entityProfile_dummy.setKeyGenerationAlgorithm(algorithm);
        when(algorithmPersistenceHandler.getAlgorithmByNameAndType(entityProfile.getKeyGenerationAlgorithm(), AlgorithmType.ASYMMETRIC_KEY_ALGORITHM)).thenReturn(algorithmData);

        entityProfileKeyGenerationAlgorithmValidator.validate(entityProfile);

    }

    /**
     * Method to test ValidateCreate method in positive scenario.
     */
    @Test(expected = AlgorithmNotFoundException.class)
    public void testCreateProfile_InValidAlgorithmData() throws FileNotFoundException {

        final EntityProfile entityProfile_dummy = entityProfile;
        final AlgorithmData algorithmData = null;
        final TrustProfile trustProfile = new TrustProfile();
        trustProfile.setName("TrustProfile_1");

        final CertificateProfile certProfile = new CertificateProfile();
        certProfile.setName("CertificateProfile_1");

        final Algorithm algorithm = new Algorithm();
        algorithm.setName("RSA");
        algorithm.setKeySize(2048);
        algorithm.setSupported(true);
        entityProfile_dummy.setKeyGenerationAlgorithm(algorithm);

        when(algorithmPersistenceHandler.getAlgorithmByNameAndType(entityProfile.getKeyGenerationAlgorithm(), AlgorithmType.ASYMMETRIC_KEY_ALGORITHM)).thenReturn(algorithmData);
        Mockito.doThrow(new AlgorithmNotFoundException("Given key generation algorithm not found")).when(keyGenerationAlgorithmValidator).validate(entityProfile.getKeyGenerationAlgorithm());
        entityProfileKeyGenerationAlgorithmValidator.validate(entityProfile);

    }

}
