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

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.cluster.classic.ClusterMessageListener;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.SynchResponseHandler;

/**
 * This listener will listen for CMPServiceTransactionCluster notifications. The notification will be delegated to <code>SynchResponseHandler</code> to handle the response.
 *
 * @author tcsswpa
 *
 */
public class CMPClusterServiceNotificationListener implements ClusterMessageListener<String> {

    @Inject
    SynchResponseHandler synchResponseHandler;

    @Inject
    Logger logger;

    static final String NODE_ID = System.getProperty("com.ericsson.oss.sdk.node.identifier");

    /**
     * This Method is invoked when a message is received from CMPServiceTransactionCluster.
     *
     * @param transactionId
     *            the messaged received from the cluster.
     */
    @Override
    public void onMessage(final String transactionId) {
        logger.info("[{}] Service instance received notification with transaction id: [{}]", NODE_ID, transactionId);
        synchResponseHandler.handleResponse(transactionId);
    }
}
