/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.cmp.common;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.ra.cmp.asynchresponse.RestSynchResponse;
import com.ericsson.oss.itpf.security.pki.ra.cmp.cluster.service.CMPServiceCluster;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;

/**
 * This class is used to handle the synch response sent from PKI-Manager
 * 
 * @author tcsswpa
 *
 */
public class SynchResponseHandler {

    @Inject
    CMPTransactionResponseMap cMPTransactionResponseMap;

    @Inject
    CMPServiceCluster cmpServiceCluster;

    @Inject
    PersistenceHandler persistenceHandler;

    @Inject
    Logger logger;

    /**
     * This method is called to check if the local <code>CMPTransactionResponseMap</code> contains the transaction id and send Synch response to network element.Otherwise it will send a cluster
     * notification to CMPServiceTransactionCluster
     * 
     * @param transactionId
     *            the entry to be checked in the local CMPTransactionResponseMap.
     * @param signedResponseMessage
     *            the response to be sent to the network element.
     */

    public void handleResponseAndSendNotification(final String transactionId, final byte[] signedResponseMessage) {
        if (cMPTransactionResponseMap.isTransactionIdExists(transactionId)) {
            logger.info("The Map contains the entry with transaction id [{}]. Sending response to Network element.", transactionId);

            final RestSynchResponse asyncResponse = cMPTransactionResponseMap.getRestSynchResponse(transactionId);
            asyncResponse.send(signedResponseMessage);
        } else {
            cmpServiceCluster.sendClusterNotification(transactionId);
        }

    }

    /**
     * This method is called to check if the local <code>CMPTransactionResponseMap</code> contains the transaction id and send Synch response to network element.
     * 
     * @param transactionId
     *            the entry to be checked in the local CMPTransactionResponseMap.
     */
    public void handleResponse(final String transactionId) {

        if (cMPTransactionResponseMap.isTransactionIdExists(transactionId)) {
            final CMPMessageEntity cmpMessageEntity = persistenceHandler.fetchEntityByTransactionID(transactionId);

            logger.info("The Map contains the entry with transaction id [{}]. Sending response to Network element.", transactionId);

            final RestSynchResponse asyncResponse = cMPTransactionResponseMap.getRestSynchResponse(transactionId);
            asyncResponse.send(cmpMessageEntity.getResponseMessage());
        } else {
            logger.debug("The Map doesn't contain any entry for transaction id [{}]", transactionId);
        }
    }
}
