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
package com.ericsson.oss.itpf.security.pki.ra.cmp.validator.common;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.NonceValidationException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.TransactionIdHandlerException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.impl.request.TransactionIdHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.MessageStatus;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.entities.CMPMessageEntity;
import com.ericsson.oss.itpf.security.pki.ra.cmp.validator.RequestValidator;

/**
 * This validator will validate whether the senderNonce are same as the recepient nonce of the previous request.
 *
 * @author tcsdemi
 *
 */
public class NonceValidator implements RequestValidator {

    @Inject
    Logger logger;

    @Inject
    TransactionIdHandler transactionIDHandler;

    @Inject
    PersistenceHandler persistenceHandler;

    @Override
    public void validate(final RequestMessage pKIRequestMessage) throws NonceValidationException, TransactionIdHandlerException {

        logger.info("Nonce Validation initiated for message : {}", pKIRequestMessage.getRequestMessage());

        final boolean tobeGenerated = false;
        String transactionId = null;

        transactionId = transactionIDHandler.handle(pKIRequestMessage, tobeGenerated);
        verifySenderNonceNull(pKIRequestMessage, transactionId);
        verifyRecepientNoncewithSenderNonce(pKIRequestMessage, transactionId);

        logger.info("Nonce Validation successful for message : {}", pKIRequestMessage.getRequestMessage());

    }

    private void updateStatusToRevoke(final RequestMessage pKIRequestMessage, final String transactionID) {
        final String senderName = pKIRequestMessage.getSenderName();
        final CMPMessageEntity cMPMessageEntity = persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionID, senderName);
        final String status = cMPMessageEntity.getStatus().toString();

        if (status == MessageStatus.WAIT_FOR_ACK.toString()) {
            cMPMessageEntity.setStatus(MessageStatus.TO_BE_REVOKED);
            persistenceHandler.updateEntity(cMPMessageEntity);
            logger.error("NonceValidation Failed, changing status to TO_BE_REVOKED for TransactionId: {} SenderName: {}", transactionID, senderName);
        }
    }

    private void verifySenderNonceNull(final RequestMessage pKIRequestMessage, final String transactionId) {

        if (pKIRequestMessage.getPKIHeader().getSenderNonce() == null) {
            updateStatusToRevoke(pKIRequestMessage, transactionId);
            logger.error("Nonce value can't be null");
            throw new NonceValidationException("Nonce Validation failed");
        }
    }

    private void verifyRecepientNoncewithSenderNonce(final RequestMessage pKIRequestMessage, final String transactionId) {

        String responseMessageSenderNonce = null;
        String requestMessageReceipientNonce = null;
        final String senderName = pKIRequestMessage.getSenderName();
        requestMessageReceipientNonce = pKIRequestMessage.getRecepientNonce();
        logger.info("requestMessage ReceipientNonce : {}" , requestMessageReceipientNonce);

        final CMPMessageEntity entity = persistenceHandler.fetchEntityByTransactionIdAndEntityName(transactionId, senderName);
        responseMessageSenderNonce = entity.getSenderNonce();

        logger.info("responseMessage SenderNonce : {}" , responseMessageSenderNonce);
        if (requestMessageReceipientNonce == null || responseMessageSenderNonce == null) {
            logger.error("Nonce value can't be null");
            throw new NonceValidationException("Nonce Validation failed");
        }

        if (!requestMessageReceipientNonce.equals(responseMessageSenderNonce)) {
            logger.error("Nonce Mismatch. Validation failed for: {}", pKIRequestMessage.getRequestMessage());
            throw new NonceValidationException("Nonce Validation failed");
        }

    }

}
