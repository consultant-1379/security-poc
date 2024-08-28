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
package com.ericsson.oss.itpf.security.pki.ra.tdps.impl;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.TrustDistributionParameters;
import com.ericsson.oss.itpf.security.pki.ra.tdps.api.exceptions.TrustDistributionServiceException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.exception.DataLookupException;
import com.ericsson.oss.itpf.security.pki.ra.tdps.common.persistence.PersistenceManager;

@RunWith(MockitoJUnitRunner.class)
public class TDPSManagerTest {

    @InjectMocks
    TDPSManager tdpsManager;

    @Mock
    PersistenceManager persistenceManager;

    @Mock
    Logger logger;

    @Mock
    TrustDistributionParameters trustDistributionParameters;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    DataLookupException dataLookupException;

    @Test
    public void testGetCertificate() {
        tdpsManager.getCertificate(trustDistributionParameters);
    }

    @Test(expected = TrustDistributionServiceException.class)
    public void testDataLookupException() {

        Mockito.when(tdpsManager.getCertificate(trustDistributionParameters)).thenThrow(new DataLookupException());
        tdpsManager.getCertificate(trustDistributionParameters);
        Mockito.verify(logger).debug("Exception StackTrace: ", new DataLookupException());
    }
}
