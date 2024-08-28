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
package com.ericsson.oss.itpf.security.pki.manager.ejb;

import javax.ejb.LocalBean;
import javax.ejb.Schedule;
import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.ejb.ExtCACRLManagement;
import com.ericsson.oss.itpf.security.pki.manager.service.cluster.MembershipListenerInterface;

@LocalBean
@Stateless
public class ExtCACRLAutomaticUpdateTimer {

    private static final Logger log = LoggerFactory.getLogger(ExtCACRLAutomaticUpdateTimer.class);

    @Inject
    MembershipListenerInterface membershipListener;

    @Inject
    ExtCACRLManagement extCACRLManager;

    @Schedule(minute = "18", hour = "1", persistent = false)
//    @Schedule(minute = "*/3", hour = "*", persistent = false)
    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public void timeoutHandler() {

        if (membershipListener.isMaster()) {
            log.info("I'm master. Start Automatic download of EXTCA CRLs");
            extCACRLManager.autoUpdateExpiredCRLs();
            log.info("End Automatic download of EXTCA CRLs");
        }
    }
}
