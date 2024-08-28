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
package com.ericsson.oss.itpf.security.pki.ra.cmp.service.scheduler;

import java.util.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.ra.cmp.common.ConfigurationParamsListener;

@RunWith(MockitoJUnitRunner.class)
public class DBCleanUpHandlerTest {

    @InjectMocks
    DBCleanUpHandler dbCleanUpHandler;

    @Mock
    Logger logger;

    @Mock
    ConfigurationParamsListener configurationParamsListener;
    
    Date modifyTime = new Date();

    @Test
    public void testCleanUpDB() {

    	final int timeout = 14;
    	Mockito.when(configurationParamsListener.getRequestTimeOut()).thenReturn(timeout);
        dbCleanUpHandler.cleanUpDB();
        Mockito.verify(logger).info("Cleaning up CMP database record from the timer service");


    }

}
