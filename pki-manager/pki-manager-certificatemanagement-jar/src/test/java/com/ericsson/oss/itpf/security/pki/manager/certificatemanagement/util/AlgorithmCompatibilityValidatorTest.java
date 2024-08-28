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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.util;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;

@RunWith(MockitoJUnitRunner.class)
public class AlgorithmCompatibilityValidatorTest {

    @InjectMocks
    AlgorithmCompatibilityValidator algorithmCompatibilityValidator;

    @Mock
    Logger logg;

    @Test(expected = InvalidEntityAttributeException.class)
    public void testcheckSignatureAndKeyGenerationAlgorithms() {

        String signatureAlgorithmName = "testname123";
        String keyGenerationAlgorithmName = "name123dfjsdh";

        algorithmCompatibilityValidator.checkSignatureAndKeyGenerationAlgorithms(signatureAlgorithmName, keyGenerationAlgorithmName);
    }

}
