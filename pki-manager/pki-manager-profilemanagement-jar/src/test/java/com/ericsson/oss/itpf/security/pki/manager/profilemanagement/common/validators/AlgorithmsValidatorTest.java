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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.validators;

import static org.mockito.Mockito.*;

import java.util.*;

import javax.persistence.PersistenceException;
import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration.AlgorithmPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.AlgorithmException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.common.data.CertificateProfileSetUpData;

/**
 * Test class for {@link AlgorithmsValidator}
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class AlgorithmsValidatorTest {

    @Mock
    private Logger logger;

    @InjectMocks
    private AlgorithmsValidator algorithmsValidator;

    @Mock
    private PersistenceManager persistenceManager;

    @Mock
    private AlgorithmPersistenceHandler algorithmPersistenceHandler;

    private CertificateProfile certificateProfile;
    private CertificateProfileData certificateProfileData;
    private Algorithm algorithm;

    private static final String ALGORITHM_NAME = "name";
    private static final String ALGORITHM_TYPE = "type";
    private static final String ALGORITHM_SUPPORTED = "supported";
    private static final String ALGORITHM_CATEGORIES = "categories";

    @Before
    public void fillData() throws DatatypeConfigurationException {
        final CertificateProfileSetUpData certificateProfileSetUpToTest = new CertificateProfileSetUpData();
        certificateProfile = certificateProfileSetUpToTest.getCertificateProfile();
        certificateProfileData = certificateProfileSetUpToTest.getCertificateProfileData();
    }

    /**
     * Method to test validateSignatureAlgorithm method in positive scenario.
     */
    @Test
    public void testValidateSignatureAlgorithm() {

        final Set<Integer> categories = new HashSet<Integer>();
        categories.add(AlgorithmCategory.OTHER.getId());

        final AlgorithmData signatureAlgorithm = certificateProfileData.getSignatureAlgorithm();

        final Map<String, Object> input = new HashMap<String, Object>();
        algorithm = certificateProfile.getSignatureAlgorithm();

        input.put(ALGORITHM_NAME, algorithm.getName());
        input.put(ALGORITHM_CATEGORIES, categories);
        input.put(ALGORITHM_TYPE, AlgorithmType.SIGNATURE_ALGORITHM.getId());
        input.put(ALGORITHM_SUPPORTED, Boolean.TRUE);

        Mockito.when(persistenceManager.findEntityWhere(AlgorithmData.class, input)).thenReturn(signatureAlgorithm);
        Mockito.when(algorithmPersistenceHandler.getAlgorithmByNameAndType(algorithm, AlgorithmType.SIGNATURE_ALGORITHM)).thenReturn(signatureAlgorithm);
        algorithmsValidator.validateSignatureAlgorithm(algorithm);
        verify(logger).debug("Validating Signature Algorithm in Certificate Profile {}", certificateProfile.getSignatureAlgorithm());
    }

    /**
     * Method to test validateSignatureAlgorithm method in negative scenario.
     */
    @Test(expected = AlgorithmNotFoundException.class)
    public void testValidateSignatureAlgorithmWithEx() {
        final Map<String, Object> signatureAlgoinput = new HashMap<String, Object>();
        when(persistenceManager.findEntityWhere(AlgorithmData.class, signatureAlgoinput)).thenReturn(null);
        algorithmsValidator.validateSignatureAlgorithm(certificateProfile.getSignatureAlgorithm());
    }

    /**
     * Method to test validateSignatureAlgorithm method in negative scenario.
     */
    @Test(expected = AlgorithmNotFoundException.class)
    public void testValidateSignatureAlgorithmWithInvlidType() {
        algorithm = certificateProfile.getSignatureAlgorithm();
        algorithm.setType(AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
        algorithmsValidator.validateSignatureAlgorithm(certificateProfile.getSignatureAlgorithm());
    }

    /**
     * Method to test validateSignatureAlgorithm method in negative scenario.
     */
    @Test(expected = AlgorithmNotFoundException.class)
    public void testValidateSignatureAlgorithmWithInvlidName() {
        algorithm = certificateProfile.getSignatureAlgorithm();
        algorithm.setName("sdkfjsdkl34");
        algorithmsValidator.validateSignatureAlgorithm(certificateProfile.getSignatureAlgorithm());
    }

    /**
     * Method to test validateSignatureAlgorithm method in negative scenario.
     */
    @Test(expected = AlgorithmNotFoundException.class)
    public void testValidateSignatureAlgorithmWithInvlidKeySize() {
        algorithm = certificateProfile.getSignatureAlgorithm();
        algorithm.setKeySize(0001);
        algorithmsValidator.validateSignatureAlgorithm(certificateProfile.getSignatureAlgorithm());
    }

    /**
     * Method to test validateSignatureAlgorithm method in negative scenario.
     */
    @Test(expected = AlgorithmException.class)
    public void testValidateSignatureAlgorithmWithNull() {
        algorithmsValidator.validateSignatureAlgorithm(null);
    }

    /**
     * Method to test validateKeyGenerationAlgorithms method in positive scenario.
     */
    //    @Test
    //    public void testValidateKeyGenerationAlgorithms() {
    //        AlgorithmData keyGenAlgData = new AlgorithmData();
    //
    //        final Set<AlgorithmData> keyGenAlgorithms = certificateProfileData.getKeyGenerationAlgorithms();
    //        for (final AlgorithmData algData : keyGenAlgorithms) {
    //            keyGenAlgData = algData;
    //        }
    //
    //        final Map<String, Object> input = new HashMap<String, Object>();
    //        final Set<Integer> categories = new HashSet<Integer>();
    //        categories.add(AlgorithmCategory.OTHER.getId());
    //
    //        input.put(ALGORITHM_NAME, keyGenAlgData.getName());
    //        input.put(ALGORITHM_CATEGORIES, categories);
    //        input.put(ALGORITHM_TYPE, AlgorithmType.ASYMMETRIC_KEY_ALGORITHM.getId());
    //        input.put(ALGORITHM_SUPPORTED, Boolean.TRUE);
    //        input.put(ALGORITHM_KEYSIZE, keyGenAlgData.getKeySize());
    //
    //        when(persistenceManager.findEntityWhere(AlgorithmData.class, input)).thenReturn(keyGenAlgData);
    //        
    //        Mockito.when(algorithmPersistenceHandler.getAlgorithmByNameAndType(new Algorithm(), AlgorithmType.ASYMMETRIC_KEY_ALGORITHM)).thenReturn(keyGenAlgData);
    //
    //        algorithmsValidator.validateKeyGenerationAlgorithms(certificateProfile.getKeyGenerationAlgorithms());
    //        verify(logger).debug("Validating KeyGenerationAlgorithmList in Certificate Profile {}", certificateProfile.getKeyGenerationAlgorithms());
    //    }

    /**
     * Method to test validateKeyGenerationAlgorithms method in negative scenario.
     */
    @Test(expected = AlgorithmException.class)
    public void testValidateKeyGenerationAlgorithmsWithNull() {
        algorithmsValidator.validateKeyGenerationAlgorithms(null);
    }

    /**
     * Method to test validateKeyGenerationAlgorithms method in negative scenario.
     */
    @Test(expected = AlgorithmNotFoundException.class)
    public void testValidateKeyGenerationAlgorithmsWithEx() {
        final Map<String, Object> keyGenAlgoinput = new HashMap<String, Object>();
        when(persistenceManager.findEntityWhere(AlgorithmData.class, keyGenAlgoinput)).thenThrow(new PersistenceException());
        algorithmsValidator.validateKeyGenerationAlgorithms(certificateProfile.getKeyGenerationAlgorithms());
    }

    @Test
    public void testValidateKeyGenerationAlgorithms() {
        final List<Algorithm> keyGenerationAlgorithmList = new ArrayList<Algorithm>();
        final Algorithm algorithm = new Algorithm();
        keyGenerationAlgorithmList.add(algorithm);

        final AlgorithmData algorithmData = new AlgorithmData();
        when(algorithmPersistenceHandler.getAlgorithmByNameAndType(algorithm, AlgorithmType.ASYMMETRIC_KEY_ALGORITHM)).thenReturn(algorithmData);

        algorithmsValidator.validateKeyGenerationAlgorithms(keyGenerationAlgorithmList);

        verify(logger, times(0)).error(Matchers.anyString());
    }

}
