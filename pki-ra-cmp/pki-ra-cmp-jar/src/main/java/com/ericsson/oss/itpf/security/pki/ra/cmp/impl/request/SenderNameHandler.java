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
package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.request;

import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.ra.cmp.persistence.PersistenceHandler;

/**
 * This class used to provide sendername for pollrequest and certconf messages
 * 
 * @author tcschdy
 *
 */
public class SenderNameHandler {

    @Inject
    PersistenceHandler persistenceHandler;

    /**
     * This method used to provide sender name for pollrequest and certconf messages
     * 
     * @param pKIRequestMessage
     *            The request message from which Transaction iD is used to fetch the sendername from DB
     * @return Sender Name
     */
    public String getSenderName(final RequestMessage pKIRequestMessage) {
        return persistenceHandler.fetchSenderNameByTransactionID(pKIRequestMessage.getBase64TransactionID());
    }
}
