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
package com.ericsson.oss.itpf.security.pki.core.service.config.listener;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.core.service.config.PKICoreConfigurationParams;
import com.ericsson.oss.itpf.security.pki.core.service.config.listener.PkiCoreConfigChangeEventListener;
import com.ericsson.oss.itpf.security.pki.core.service.scheduling.CRLGenerationTimerServiceBean;

@RunWith(MockitoJUnitRunner.class)
public class PkiCoreConfigChangeEventListenerTest {

    @InjectMocks
    PkiCoreConfigChangeEventListener pkiCoreConfigChangeEventListener;

    @Mock
    private PKICoreConfigurationParams pkiCoreConfiguraionParams;

    @Mock
    private CRLGenerationTimerServiceBean crlGenerationTimerServiceBean;

    @Mock
    SystemRecorder systemRecorder;

    @Mock
    Logger logger;

    @Test
    public void testListenForChangedConfigParamGenerateCRLSchedulerTime() {
        final String generateCRLSchedulerTime = "*,*,*,*,1,1,0";
        pkiCoreConfigChangeEventListener.listenForGenerateCRLSchedularTime(generateCRLSchedulerTime);
    }
}
