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
package com.ericsson.oss.itpf.security.pki.manager.ejb.test;

import java.io.IOException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.manager.ejb.SupportedAlgorithmsCacheInitializer;
import com.ericsson.oss.itpf.security.pki.manager.scep.helper.SupportAlgorithmsCacheOperations;

@RunWith(MockitoJUnitRunner.class)
public class SupportedAlgorithmsCacheInitializerTest {

    @InjectMocks
    SupportedAlgorithmsCacheInitializer supportedAlgorithmsCacheInitializer;

    @Mock
    private Logger logger;

    @Mock
    private SupportAlgorithmsCacheOperations supportAlgCacheOperations;


    @Test
    public void testCacheLoading() throws IOException {

        Mockito.doNothing().when(supportAlgCacheOperations).loadSupportedAlgorithms();
        supportedAlgorithmsCacheInitializer.initializeCache();
        Mockito.verify(supportAlgCacheOperations).loadSupportedAlgorithms();

    }

}
