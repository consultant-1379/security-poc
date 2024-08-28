/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.pki.ra.cmp.service.cluster;

import javax.ejb.ConcurrencyManagement;
import javax.ejb.ConcurrencyManagementType;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.cluster.MembershipChangeEvent;
import com.ericsson.oss.itpf.sdk.cluster.MembershipChangeEvent.ClusterMemberInfo;
import com.ericsson.oss.itpf.sdk.cluster.annotation.ServiceCluster;

/**
 * This class will provide the observer method will be invoked by ServiceFramework every time there are membership changes in service cluster named
 * PKIRACMPMastershipCluster
 *
 * @author xnagsow
 */
@ApplicationScoped
@ConcurrencyManagement(ConcurrencyManagementType.BEAN)
public class MembershipListener implements MembershipListenerInterface {

    private static final Logger log = LoggerFactory.getLogger(MembershipListener.class);

    volatile boolean master;

    /**
     * Observer method will be invoked by ServiceFramework every time there are membership changes in service cluster named PKIRACMPMastershipCluster
     *
     * @param mce
     *            MembershipChangeEvent object
     */
    void listenForMembershipChange(@Observes @ServiceCluster("PKIRACMPMastershipCluster") final MembershipChangeEvent mce) {
        log.info("Catch MemberShip Change for pki-ra-cmp isMaster: {}", mce.isMaster());
        setMaster(mce.isMaster());
        final int numberOfMembers = mce.getCurrentNumberOfMembers();
        log.info("MemberShip: {}" , numberOfMembers);
        for (final ClusterMemberInfo cmi : mce.getAllClusterMembers()) {
            log.info("NodeId: {} ServiceId: {} Version: {}", cmi.getNodeId(), cmi.getServiceId(), cmi.getVersion());
        }
    }

    @Override
    public boolean isMaster() {
        return master;
    }

    private void setMaster(final boolean master) {
        this.master = master;
    }

}
