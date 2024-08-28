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
package com.ericsson.oss.itpf.security.pki.manager.rest.util;

import static org.junit.Assert.assertNotNull;

import java.io.IOException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.rest.dto.ErrorMessageDTO;

/**
 * This class will test LoadErrorPropertiesTest
 * 
 * @author tcsrav
 * 
 */
@RunWith(MockitoJUnitRunner.class)
public class LoadErrorPropertiesTest {

    @InjectMocks
    LoadErrorProperties loadErrorProperties;

    @Mock
    ErrorMessageDTO errorMessageDTO;

    /**
     * Method to test Positive scenario
     * 
     */
    @Test
    public void testGetErrorMessageDTOdefault() {

        errorMessageDTO = loadErrorProperties.getErrorMessageDTO("Test");
        assertNotNull(errorMessageDTO);
    }

    /**
     * Method to test Negative scenario
     * 
     */
    @Test
    public void testGetErrorMessageDTO() throws IOException {

        loadErrorProperties.startup();
        errorMessageDTO = loadErrorProperties.getErrorMessageDTO("Entity Name is required to issue certificate");
        assertNotNull(errorMessageDTO);
    }
}
