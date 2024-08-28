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
package com.ericsson.oss.itpf.security.pki.ra.tdps.service.ejb;

import java.io.IOException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Matchers;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.eventbus.model.EventSender;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPServiceRequest;

@RunWith(MockitoJUnitRunner.class)
public class TrustDistributionPointServiceStartupBeanTest {

    @InjectMocks
    TrustDistributionPointServiceStartupBean trustDistributionPointServiceStartupBean;

    @Mock
    EventSender<TDPServiceRequest> tDPSServiceRequestEventSender;

    @Mock
    Logger logger;

    @Mock
    private SystemRecorder systemRecorder;

    @Test
    public void testOnServiceStart() {

        trustDistributionPointServiceStartupBean.onServiceStart();
        Mockito.verify(tDPSServiceRequestEventSender).send(Matchers.<TDPServiceRequest> anyObject());

    }

    @Test
    public void testOnServiceStartException() {

        Mockito.doThrow(IOException.class).when(tDPSServiceRequestEventSender).send(Mockito.<TDPServiceRequest> anyObject());

        trustDistributionPointServiceStartupBean.onServiceStart();
        Mockito.verify(logger).info("Publishing initial event for fetching all published and active certificates");

    }

}