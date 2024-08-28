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
package com.ericsson.oss.itpf.security.pki.ra.cmp.cluster.service;

import javax.annotation.PostConstruct;
import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.cluster.classic.ServiceClusterBean;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;

/**
 * CMPServiceCluster class holds the CMPServiceTransactionCluster cluster instance. This class is used to join, leave the current service cluster. It is also used to send notifications to all members
 * of current service cluster.
 *
 * @author tcsswpa
 *
 */
@ApplicationScoped
public class CMPServiceCluster {

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    Logger logger;

    @Inject
    CMPClusterServiceNotificationListener cmpClusterServiceNotificationListener;

    final String nodeId = System.getProperty("com.ericsson.oss.sdk.node.identifier");
    private static final String CLUSTERNAME = "CMPServiceTransactionCluster";

    ServiceClusterBean serviceClusterBean = null;

    @PostConstruct
    void initializeCluster() {
        try {
            serviceClusterBean = new ServiceClusterBean(CLUSTERNAME);
        } catch (final Exception exception) {
            logger.error("[{}] service instance failed to initialize cluster [{}].", nodeId, CLUSTERNAME);
            logger.warn("Failed to initialize the cluster due to ", exception);
            systemRecorder.recordError("CMP StartUp Service", ErrorSeverity.CRITICAL, "initializing " + CLUSTERNAME + " for " + nodeId, "CMP_STARTUP_SERVICE.INITIALIZE_CLUSTER ",
                    "Enrollment of Rodio (T) node willn't be supported.");
        }
    }

    /**
     * This method is invoked to join the cluster. It also attaches message listener to receive messages.
     */
    public void joinCluster() {

        boolean joinedCluster = false;
        try {
            joinedCluster = serviceClusterBean.joinCluster(cmpClusterServiceNotificationListener);
        } catch (final Exception exception) {
            logger.error("[{}] service instance failed to join cluster [{}].", nodeId, CLUSTERNAME);
            logger.warn("Failed to join the cluster due to ", exception);
            systemRecorder.recordError("CMP StartUp Service", ErrorSeverity.CRITICAL, "Joining " + CLUSTERNAME + " for " + nodeId, "CMP_STARTUP_SERVICE.JOIN_CLUSTER ",
                    "Enrollment of Rodio (T) node willn't be supported.");
        }

        if (joinedCluster) {
            logger.debug("[{}] service instance joined cluster [{}] successfully.", nodeId, CLUSTERNAME);
        } else {
            logger.error("[{}] service instance failed to join cluster [{}].", nodeId, CLUSTERNAME);
            systemRecorder.recordError("CMP StartUp Service", ErrorSeverity.CRITICAL, "Joining " + CLUSTERNAME + " for " + nodeId, "CMP_STARTUP_SERVICE.JOIN_CLUSTER ",
                    "Enrollment of Rodio (T) node willn't be supported.");
        }
    }

    /**
     * This method is invoked to leave cluster.
     */
    public void leaveCluster() {
        if (serviceClusterBean.isClusterMember()) {
            logger.debug("[{}] is leaving cluster [{}]", nodeId, CLUSTERNAME);
            serviceClusterBean.leaveCluster();
        }
    }

    /**
     * This method is used to send a signal message to all members of current service cluster.
     *
     * @param transactionId
     *            to message to be sent.
     */
    public void sendClusterNotification(final String transactionId) {
        if (serviceClusterBean != null && serviceClusterBean.isClusterMember()) {
            logger.debug("[{}] is sending cluster notification to cluster [{}] with Transaction id: {}", nodeId, CLUSTERNAME, transactionId);
            serviceClusterBean.send(transactionId);
        } else {
            logger.error("[{}] is unable to send cluster notification to cluster [{}] with Transaction id [{}]", nodeId, CLUSTERNAME, transactionId);
        }
    }
}
