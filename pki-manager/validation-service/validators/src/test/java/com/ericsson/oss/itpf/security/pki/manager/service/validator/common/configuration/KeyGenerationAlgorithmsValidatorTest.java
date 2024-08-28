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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.common.configuration;

import java.util.ArrayList;
import java.util.List;

import javax.xml.datatype.DatatypeConfigurationException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.AlgorithmException;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.data.EntityProfileSetUpData;

@RunWith(MockitoJUnitRunner.class)
public class KeyGenerationAlgorithmsValidatorTest {
    @Mock
    Logger logger;

    @InjectMocks
    KeyGenerationAlgorithmsValidator keyGenerationAlgorithmsValidator;

    @Mock
    KeyGenerationAlgorithmValidator keyGenerationAlgorithmValidator;

    /**
     * Method to test validate method in positive scenario.
     *
     * @throws DatatypeConfigurationException
     */
    @Test
    public void testKeyGenerationAlgorithms_ValidParams() throws DatatypeConfigurationException {
        final EntityProfileSetUpData entityProfileSetUpData = new EntityProfileSetUpData();
        final List<Algorithm> keyGenerationAlgorithms = new ArrayList<Algorithm>();
        keyGenerationAlgorithms.add(entityProfileSetUpData.getEntityProfile().getKeyGenerationAlgorithm());
        keyGenerationAlgorithmsValidator.validate(keyGenerationAlgorithms);
        Mockito.verify(logger).debug("Validating KeyGenerationAlgorithmList in Certificate Profile {}", keyGenerationAlgorithms);

    }

    /**
     * Method to test validate method in negative scenario.
     *
     * @throws DatatypeConfigurationException
     */
    @Test(expected = AlgorithmException.class)
    public void testKeyGenerationAlgorithms_NullAlgorithmData() throws DatatypeConfigurationException {

        keyGenerationAlgorithmsValidator.validate(null);
    }

}
