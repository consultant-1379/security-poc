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
package com.ericsson.oss.itpf.security.pki.ra.cmp.cluster.ejb;

import javax.annotation.PostConstruct;
import javax.annotation.PreDestroy;
import javax.ejb.Singleton;
import javax.ejb.Startup;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.ra.cmp.cluster.service.CMPServiceCluster;

/**
 * This class will initialize the <code>CMPServiceCluster</code>.
 * 
 * @author tcsswpa
 *
 */
@Startup
@Singleton
public class CMPClusterServiceBean {

    @Inject
    CMPServiceCluster cmpServiceCluster;

    @Inject
    Logger logger;

    /**
     * This method is called to join the CMPServiceTransactionCluster.
     */
    @PostConstruct
    void joinClusterService() {
        logger.debug("PostConstruct method called to join cluster");
        cmpServiceCluster.joinCluster();
    }

    /**
     * This method is called to join the CMPServiceTransactionCluster.
     */
    @PreDestroy
    void leaveClusterService() {
        logger.debug("PreDestory method called to leave cluster");
        cmpServiceCluster.leaveCluster();
    }
}
