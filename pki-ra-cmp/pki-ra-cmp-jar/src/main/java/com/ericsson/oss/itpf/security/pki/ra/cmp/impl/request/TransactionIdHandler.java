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
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.TransactionIdHandlerException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;

/**
 * This class is a handler which deals with generation of transactionId if null, verifying transaction Id in case of different request types.<br>
 * Refer to the Method: <code> String handle(final RequestMessage pKIRequestMessage, final boolean tobeGenerated) throws TransactionIdHandlerException </code>
 *
 * @author tcsdemi
 *
 */
public class TransactionIdHandler {
    @Inject
    Logger logger;

    @Inject
    PersistenceHandler persistenceHandler;

    @Inject
    TransactionIdGenerator transactionIDGenerator;

    /**
     * This method accepts RequestMessage and a boolean whether or not for a particular request transaction is to be generated or not. <br>
     * For eg: In case of IntializationRequest[IR] and Key update Request[KUR] transactionID needs to be generated [if null] since there will not be any DBentry for the same. Hence tobeGenerated will
     * be true in respective RequestHandlers. <br>
     * Cases:
     * <p>
     * 1. In case it is an IR or KUR, isGenerated is true and in pkiRequestMessage transactionID is null then transaction ID needs to be generated.
     * <p>
     * 2. In case it is Pollrequest/certConfRequest isGenerated will be false, but in pkiRequestMessage transactionID should be present. If not then exception is thrown as HEADER_TRANSACTION_EMPTY.
     * <p>
     * 3.In case for IR/KUR transactionID is present in pkiRequestMessage but already it exists in DB then TRANSACTION_ID_IN_USE is thrown
     * <p>
     * 4. In case of PollRequest/certConfRequest transaction is present in pkiRequestMessage but not present in DB then TRANSACTION_ID_NOT_FOUND is thrown.
     *
     * @param pKIRequestMessage
     * @param tobeGenerated
     * @return
     * @throws TransactionIdHandlerException
     *             Thrown in case transactionId is not received or not present int DB.
     */

    public String handle(final RequestMessage pKIRequestMessage, final boolean tobeGenerated) throws TransactionIdHandlerException {

        String transactionId = null;
        final String senderName = pKIRequestMessage.getSenderName();
        logger.info("Validating transactionID for :{} ", pKIRequestMessage.getRequestMessage());
        if (pKIRequestMessage.getBase64TransactionID() == null) {
            if (tobeGenerated) {
                logger.debug("TransactionID is to be generated, generating a unique ID");
                transactionId = transactionIDGenerator.generateUniqueTransactionID(pKIRequestMessage);
                pKIRequestMessage.setBase64TransactionID(transactionId);

            } else {
                logger.error("TransactionID should be present in DB, in case of PollReq/CertConf following IR and KUR");
                throw new TransactionIdHandlerException(ErrorMessages.TRANSACTIONID_RECVD_NULL);
            }

        } else {
            transactionId = pKIRequestMessage.getBase64TransactionID();
            logger.debug("Transaction is present in the message :{}", transactionId);
            if (tobeGenerated) {
                if (persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionId, senderName) != null) {
                    logger.error("TransactionID received from Node is already present in database, which shouldn't be case for intialization or key update request ");
                    throw new TransactionIdHandlerException(ErrorMessages.TRANSACTION_ID_IN_USE);
                }
            } else {
                if (persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionId, senderName) == null) {
                    logger.error("Transaction couldn't be found in DB for Polling/certConf.");
                    throw new TransactionIdHandlerException(ErrorMessages.TRANSACTION_ID_NOT_FOUND);
                }
            }
        }
        logger.info("Validated TransactionID and unique transaction generated or already existing in request is :{} ", transactionId);
        return transactionId;
    }

}
