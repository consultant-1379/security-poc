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

import javax.ejb.ConcurrencyManagement;
import javax.ejb.ConcurrencyManagementType;
import javax.enterprise.context.ApplicationScoped;
import javax.enterprise.event.Observes;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.cluster.MembershipChangeEvent;
import com.ericsson.oss.itpf.sdk.cluster.MembershipChangeEvent.ClusterMemberInfo;
import com.ericsson.oss.itpf.sdk.cluster.annotation.ServiceCluster;

/**
 * This listener class is used to invoked by ServiceFramework every time there are membership changes in service cluster
 * 
 * @author xchowja
 *
 */
@ApplicationScoped
@ConcurrencyManagement(ConcurrencyManagementType.BEAN)
public class PKIRAMembershipListener implements PKIRAMembershipListenerInterface {

    @Inject
    private Logger log;
    volatile boolean master = false;

    // observer method will be invoked by ServiceFramework every time there are membership changes in service cluster
    void listenForMembershipChange(@Observes @ServiceCluster("PKIRAMastershipCluster") final MembershipChangeEvent mce) {
        log.info("Catch MemberShip Change in PKIRAMembershipListener [isMaster = " + mce.isMaster() + "]");
        setMaster(mce.isMaster());

        final int numberOfMembers = mce.getCurrentNumberOfMembers();
        log.info("MemberShip in PKIRAMembershipListener: {} ", numberOfMembers);
        for (final ClusterMemberInfo cmi : mce.getAllClusterMembers()) {
            log.info("NodeId: " + cmi.getNodeId() + " ServiceId: " + cmi.getServiceId() + " Version: " + cmi.getVersion());
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