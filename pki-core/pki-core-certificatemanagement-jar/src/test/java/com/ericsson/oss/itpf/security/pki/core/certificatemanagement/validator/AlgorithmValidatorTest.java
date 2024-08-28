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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.validator;

import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test.BaseTest;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.AlgorithmData;
import com.ericsson.oss.itpf.security.pki.core.exception.configuration.AlgorithmValidationException;

@RunWith(MockitoJUnitRunner.class)
@SuppressWarnings("PMD.UnusedPrivateField")
public class AlgorithmValidatorTest extends BaseTest {

    @InjectMocks
    private AlgorithmValidator algorithmValidator;

    private Algorithm keyGenerationAlgorithm;
    private AlgorithmData algorithmData;

    /**
     * Prepares initial data.
     * 
     */
    @Before
    public void setUpBeforeClass() {

        keyGenerationAlgorithm = prepareKeyGenerationAlgorithm();

        algorithmData = new AlgorithmData();
    }

    /**
     * Method to test {@link AlgorithmData}
     */
    @Test
    public void testValidateAlgorithm() {

        Mockito.when(persistenceHelper.getAlgorithmData(keyGenerationAlgorithm)).thenReturn(algorithmData);

        algorithmValidator.validateAlgorithm(keyGenerationAlgorithm);

        Mockito.verify(persistenceHelper).getAlgorithmData(keyGenerationAlgorithm);
    }

    /**
     * Method to test {@link AlgorithmData} when {@link AlgorithmValidationException} occurred.
     */
    @Test(expected = AlgorithmValidationException.class)
    public void testValidateAlgorithm_AlgorithmvalidationException() {

        Mockito.when(persistenceHelper.getAlgorithmData(keyGenerationAlgorithm)).thenReturn(null);

        algorithmValidator.validateAlgorithm(keyGenerationAlgorithm);
    }
}