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
package com.ericsson.oss.itpf.security.pki.core.service.cluster;

import java.util.ArrayList;
import java.util.List;

import org.junit.Assert;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.sdk.cluster.MembershipChangeEvent;

@RunWith(MockitoJUnitRunner.class)
public class MembershipListenerTest {

    MembershipListener underTest;

    @Test
    public void isMaster() {
        underTest = new MembershipListener();
        Assert.assertFalse(underTest.isMaster());
        
        final MembershipChangeEventImpl mce = new MembershipChangeEventImpl();
        
        mce.setMaster(true);
        underTest.listenForMembershipChange(mce);
        Assert.assertTrue(underTest.isMaster());
        
        mce.setMaster(false);
        underTest.listenForMembershipChange(mce);
        Assert.assertFalse(underTest.isMaster());
    }

    class MembershipChangeEventImpl implements MembershipChangeEvent {

        boolean isMaster = true;

        @Override
        public List<ClusterMemberInfo> getAllClusterMembers() {
            final List<ClusterMemberInfo> ret = new ArrayList<ClusterMemberInfo>();
            ret.add(new ClusterMemberInfo("sps", "1", "42.42"));
            ret.add(new ClusterMemberInfo("sps", "2", "43.43"));
            return ret;
        }

        @Override
        public int getCurrentNumberOfMembers() {
            return 0;
        }

        @Override
        public List<ClusterMemberInfo> getRemovedMembers() {
            return null;
        }

        @Override
        public boolean isMaster() {
            return this.isMaster;
        }

        void setMaster(final boolean isMaster) {
            this.isMaster = isMaster;
        }
    }
}