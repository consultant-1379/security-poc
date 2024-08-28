/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.ejb;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.InjectMocks;
import org.mockito.Mock;
import org.mockito.Mockito;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.ejb.ExtCACRLManagement;
import com.ericsson.oss.itpf.security.pki.manager.service.cluster.MembershipListenerInterface;

@RunWith(MockitoJUnitRunner.class)
public class ExtCACRLAutomaticUpdateTimerTest {

    @Mock
    MembershipListenerInterface membershipListener;

    @Mock
    ExtCACRLManagement extCACRLManager;

    @InjectMocks
    ExtCACRLAutomaticUpdateTimer extCACRLAutomaticUpdateTimer;

    @Test
    public void timeoutHandlerIsMaster() {
        Mockito.when(membershipListener.isMaster()).thenReturn(true);
        extCACRLAutomaticUpdateTimer.timeoutHandler();
    }

    @Test
    public void timeoutHandlerIsSlave() {
        Mockito.when(membershipListener.isMaster()).thenReturn(false);
        extCACRLAutomaticUpdateTimer.timeoutHandler();
    }
}
