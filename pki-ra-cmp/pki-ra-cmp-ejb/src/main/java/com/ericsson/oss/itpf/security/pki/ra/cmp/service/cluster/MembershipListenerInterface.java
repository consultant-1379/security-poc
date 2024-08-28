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

/**
 * This is an interface for MembershipListener class which is used to update the mastership status for the PKIRACMP cluster every time there are
 * membership changes in service cluster named
 * PKIRACMPMastershipCluster
 * 
 * @author xnagsow
 */
public interface MembershipListenerInterface {

    /**
     * This method will check whether the current listener is master of logical service cluster or not.
     * 
     * @return true if current listener is master of logical service cluster or false otherwise.
     */
    boolean isMaster();

}
