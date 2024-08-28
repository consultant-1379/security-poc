/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.request;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Base64EncodedIdGenerator;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;

/**
 * This class will have methods required for transaction Id generation. Currently this class has <code>generateUniqueTransactionID(final RequestMessage pKIRequestMessage)</code> which returns a Base64
 * Encoded string. In case any other encoder needs to be applied then new methods can be written in this class.
 * 
 * @author tcsdemi
 *
 */
public class TransactionIdGenerator {
    @Inject
    Logger logger;

    @Inject
    PersistenceHandler persistenceHandler;

    /**
     * This method generates a unique transaction for a particular senderName(entity) i.e there can be same transactionID for two different entities but for the same entity transactionID can not be
     * repeated in the system. TransactionId generated is a base64Encoded.
     * 
     * @param pKIRequestMessage
     * @return transactionID (String)
     */
    public String generateUniqueTransactionID(final RequestMessage pKIRequestMessage) {
        boolean isUniqueTRID = false;
        String transactionID = null;
        final String senderName = pKIRequestMessage.getSenderName();
        while (!isUniqueTRID) {
            transactionID = Base64EncodedIdGenerator.generate();
            logger.info("Newly generated TransactionID is: {} ", transactionID, "checking again inDB for this newly created TransactionID");
            if (persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName) == null) {
                isUniqueTRID = true;
            }
        }
        return transactionID;
    }

}
