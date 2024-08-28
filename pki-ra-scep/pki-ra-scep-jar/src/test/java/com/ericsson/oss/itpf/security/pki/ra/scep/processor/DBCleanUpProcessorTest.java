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
package com.ericsson.oss.itpf.security.pki.ra.scep.processor;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.scep.configuration.listener.ConfigurationListener;
import com.ericsson.oss.itpf.security.pki.ra.scep.persistence.PersistenceHandler;

/**
 * The class contains test for DbCleanUpProcessor
 */
@RunWith(MockitoJUnitRunner.class)
public class DBCleanUpProcessorTest {

    @InjectMocks
    private DBCleanUpProcessor dbCleanUpProcessor;

    @Mock
    PersistenceHandler persistanceHandler;

    @Mock
    ConfigurationListener configurationListener;

    @Mock
    private Logger logger;

    @Mock
    private SystemRecorder systemRecorder;

    /**
     * This method test the DB clean up for a given schedule time
     */
    @Test
    public void testCleanUpOldRecordsFromSCEPDB() {
        final int PURGE_PERIOD = 24;
        Mockito.when(configurationListener.getScepRequestRecordPurgePeriod()).thenReturn(PURGE_PERIOD);
        dbCleanUpProcessor.cleanUpOldRecordsFromSCEPDB(PURGE_PERIOD);
        Mockito.verify(persistanceHandler).deleteOldRecordsFromScepDb(Mockito.anyInt());
    }
}
