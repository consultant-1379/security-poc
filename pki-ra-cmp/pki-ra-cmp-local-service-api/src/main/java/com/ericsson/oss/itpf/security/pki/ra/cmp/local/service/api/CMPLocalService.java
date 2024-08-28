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
package com.ericsson.oss.itpf.security.pki.ra.cmp.local.service.api;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.MessageStatus;

/**
 * This interface is used to update the CMP transaction status in pkiracmp DB using required parameters
 * 
 * @author xchowja
 *
 */
@EService
@Local
public interface CMPLocalService {
    /**
     * This interface is used to update the CMP transaction status in pkiracmp DB using required parameters
     * 
     * @param transactionID
     * @param senderName
     * @param signedResponse
     * @param status
     * @param errorInfo
     */
    void updateCMPTransactionStatus(final String transactionID, final String senderName, final byte[] signedResponse, MessageStatus status, final String errorInfo);

    /**
     * This interface is used to update the CMP transaction status in pkiracmp DB using required parameters
     * 
     * @param transactionID
     * @param senderName
     * @param signedResponse
     * @param senderNonce
     * @param errorInfo
     */
    void updateCMPTransactionStatus(final String transactionID, final String senderName, final byte[] signedResponse, final String senderNonce, final String errorInfo);
}
