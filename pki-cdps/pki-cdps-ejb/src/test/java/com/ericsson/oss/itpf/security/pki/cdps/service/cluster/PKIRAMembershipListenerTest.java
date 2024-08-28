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
package com.ericsson.oss.itpf.security.pki.cdps.service.cluster;

import java.util.ArrayList;
import java.util.List;

import org.slf4j.Logger;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.sdk.cluster.MembershipChangeEvent;
import com.ericsson.oss.itpf.sdk.cluster.MembershipChangeEvent.ClusterMemberInfo;

/**
 * Test Class for PKIRAMembershipListener.
 * 
 * @author xkumkam
 *
 */
@RunWith(MockitoJUnitRunner.class)
public class PKIRAMembershipListenerTest {

    @InjectMocks
    PKIRAMembershipListener pkiraMembershipListener;

    @Mock
    MembershipChangeEvent membershipChangeEvent;

    @Mock
    Logger log;

    volatile boolean master = false;
    private final String nodeId = "12345";
    private final String serviceId = "12";
    private final String version = "1.2.0";

    @Test
    public void testListenForMembershipChange() {
        List<ClusterMemberInfo> ClusterMemberInfos = new ArrayList<ClusterMemberInfo>();
        ClusterMemberInfo ClusterMemberInfo = new ClusterMemberInfo(nodeId, serviceId, version);
        ClusterMemberInfos.add(ClusterMemberInfo);
        Mockito.when(membershipChangeEvent.getAllClusterMembers()).thenReturn(ClusterMemberInfos);
        
        pkiraMembershipListener.listenForMembershipChange(membershipChangeEvent);
        
        Mockito.verify(log).info("Catch MemberShip Change in PKIRAMembershipListener [isMaster = false]");
        Mockito.verify(log).info("NodeId: 12345 ServiceId: 12 Version: 1.2.0");
    }
}
