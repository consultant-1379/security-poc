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
package com.ericsson.oss.itpf.security.pki.ra.scep.service.cluster;

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
 * This class is used to update the mastership status for the PKIRASCEP cluster every time there are membership changes in service cluster named PKIRASCEPMastershipCluster
 * 
 * @author xnagsow
 *
 */
@ApplicationScoped
@ConcurrencyManagement(ConcurrencyManagementType.BEAN)
public class MembershipListener implements MembershipListenerInterface {

    private static final Logger log = LoggerFactory.getLogger(MembershipListener.class);

    volatile boolean master = false;

    /**
     * This method will be invoked by ServiceFramework every time there are membership changes in service cluster named PKIRAMastershipCluster
     * 
     * @param mce
     *            An object of type MembershipChangeEvent. In case of membership change, master instance will always receive notification of this
     *            event
     */
    void listenForMembershipChange(@Observes @ServiceCluster("PKIRASCEPMastershipCluster") final MembershipChangeEvent mce) {
        log.info("Catch SCEP MemberShip Change [isMaster = " + mce.isMaster() + "]");
        setMaster(mce.isMaster());
        final int numberOfMembers = mce.getCurrentNumberOfMembers();
        log.info("MemberShip: " + numberOfMembers);
        for (final ClusterMemberInfo cmi : mce.getAllClusterMembers()) {
            log.info("NodeId: " + cmi.getNodeId() + " ServiceId: " + cmi.getServiceId() + " Version: " + cmi.getVersion());
        }
    }

    public boolean isMaster() {
        return master;
    }

    private void setMaster(final boolean master) {
        this.master = master;
    }

}