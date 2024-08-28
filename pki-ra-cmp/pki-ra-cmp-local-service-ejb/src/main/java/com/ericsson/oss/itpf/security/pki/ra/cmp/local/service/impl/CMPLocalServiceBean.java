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
package com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.impl;

import javax.ejb.Stateless;
import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.api.CMPLocalService;
import com.ericsson.oss.itpf.security.pki.ra.cmp.notification.Constants;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.MessageStatus;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;

/**
 * This interface is used to update the CMP transaction status in pkiracmp DB using required transactionID,senderName,signedResponse,status and senderNonce
 * 
 * @author xchowja
 *
 */
@Stateless
public class CMPLocalServiceBean implements CMPLocalService {
    @Inject
    PersistenceHandler persistenceHandler;

    @Inject
    Logger logger;

    @Override
    public void updateCMPTransactionStatus(final String transactionID, final String senderName, final byte[] signedResponse, MessageStatus status, final String errorInfo) throws PersistenceException {

        logger.info("Storing CMP response message with transaction id [{}], entity name [{}] and updating status [{}].", transactionID, senderName, status);
        if (!isNullorEmpty(errorInfo) && !Constants.NO_ERROR_INFO.equals(errorInfo)) {
            status = MessageStatus.FAILED;
        }
        persistenceHandler.updateCMPTransactionStatus(transactionID, senderName, signedResponse, status);
    }

    @Override
    public void updateCMPTransactionStatus(final String transactionID, final String senderName, final byte[] signedResponse, final String senderNonce, final String errorInfo) {
        MessageStatus status = MessageStatus.WAIT_FOR_ACK;
        if (!isNullorEmpty(errorInfo) && !Constants.NO_ERROR_INFO.equals(errorInfo)) {
            status = MessageStatus.FAILED;
        } 
        logger.debug("Storing CMP response message with transaction id [{}], entity name [{}] and updating status to {}.", transactionID, senderName, status);
        persistenceHandler.updateCMPTransactionStatus(transactionID, senderName, signedResponse, status, senderNonce);
    }

    private boolean isNullorEmpty(final String str){
        return (str == null || str.trim().isEmpty());
    }
}
