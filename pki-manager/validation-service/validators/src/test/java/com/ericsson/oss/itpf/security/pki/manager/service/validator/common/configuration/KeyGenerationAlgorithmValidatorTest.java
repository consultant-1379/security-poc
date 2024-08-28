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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.common.configuration;

import static org.mockito.Mockito.when;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.Spy;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmType;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.configuration.AlgorithmPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.AlgorithmException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntityProfileSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class KeyGenerationAlgorithmValidatorTest {

    @Spy
    Logger logger = LoggerFactory.getLogger(KeyGenerationAlgorithmValidator.class);

    @InjectMocks
    KeyGenerationAlgorithmValidator keyGenerationAlgorithmValidator;

    @Mock
    AlgorithmPersistenceHandler algorithmPersistenceHandler;

    /**
     * This method tests validate method in positive scenario.
     *
     * @throws DatatypeConfigurationException
     */
    @Test
    public void testKeyGenerationAlgorithms_ValidParams() throws DatatypeConfigurationException {
        final EntityProfileSetUpData entityProfileSetUpData = new EntityProfileSetUpData();

        when(
                algorithmPersistenceHandler.getAlgorithmByNameAndType(entityProfileSetUpData.getEntityProfile().getKeyGenerationAlgorithm(),
                        AlgorithmType.ASYMMETRIC_KEY_ALGORITHM)).thenReturn(entityProfileSetUpData.getAlgorithmData());
        keyGenerationAlgorithmValidator.validate(entityProfileSetUpData.getEntityProfile().getKeyGenerationAlgorithm());
        Mockito.verify(algorithmPersistenceHandler).getAlgorithmByNameAndType(entityProfileSetUpData.getEntityProfile().getKeyGenerationAlgorithm(),
                AlgorithmType.ASYMMETRIC_KEY_ALGORITHM);
    }

    /**
     * This method tests validate method in negative scenario.
     *
     * @throws DatatypeConfigurationException
     */
    @Test(expected = AlgorithmNotFoundException.class)
    public void testKeyGenerationAlgorithms_NullAlgorithmData() throws DatatypeConfigurationException {
        final EntityProfileSetUpData entityProfileSetUpData = new EntityProfileSetUpData();

        when(
                algorithmPersistenceHandler.getAlgorithmByNameAndType(entityProfileSetUpData.getEntityProfile().getKeyGenerationAlgorithm(),
                        AlgorithmType.ASYMMETRIC_KEY_ALGORITHM)).thenReturn(null);
        keyGenerationAlgorithmValidator.validate(entityProfileSetUpData.getEntityProfile().getKeyGenerationAlgorithm());
    }

    /**
     * This method tests validate method in negative scenario.
     *
     * @throws DatatypeConfigurationException
     */
    @Test(expected = AlgorithmException.class)
    public void testKeyGenerationAlgorithms_NullAlgorithm() throws DatatypeConfigurationException {

        keyGenerationAlgorithmValidator.validate(null);
    }

}
