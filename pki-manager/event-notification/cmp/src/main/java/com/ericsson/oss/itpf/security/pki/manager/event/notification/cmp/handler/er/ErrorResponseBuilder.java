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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.er;

import java.io.IOException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.FailureResponseMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Base64EncodedIdGenerator;

/**
 * This class is responsible for building failure response message.
 * 
 * @author tcsramc
 * 
 */
public class ErrorResponseBuilder {

    @Inject
    Logger logger;

    /**
     * This method is used to build Failure CMPServiceResponse based on requestMessage. forms defaultErrorResponse if requestmessage is null else it generates failure Response Message with the error
     * message and transactionId.
     * 
     * @param errorMessage
     *            Error Message to build Failure CMPServiceResponse
     * @param transactionID
     *            transactionID
     * @param pKIRequestMessage
     *            RequestMessage
     * @return returns CMPServiceResponse
     * @throws IOException
     */
    public FailureResponseMessage build(final String errorMessage, final String transactionID, final RequestMessage pKIRequestMessage, final X509Certificate x509Certificate) throws IOException {
        FailureResponseMessage failureResponseMessage = null;
        failureResponseMessage = generateFailureResponseMessage(errorMessage, transactionID, pKIRequestMessage, x509Certificate);
        return failureResponseMessage;
    }

    private FailureResponseMessage generateFailureResponseMessage(final String errorMessage, final String transactionID, final RequestMessage pKIRequestMessage, final X509Certificate x509Certificate)
            throws IOException {

        final String issuer = "CN=dummy";
        final String senderNonce = Base64EncodedIdGenerator.generate();
        final String recipientNonce = pKIRequestMessage.getSenderNonce();
        final byte[] encodedProtectionAlgorithm = pKIRequestMessage.getProtectAlgorithm().getEncoded();
        final String recipient = pKIRequestMessage.getSenderName();

        final FailureResponseMessage failureResponseMessage = new FailureResponseMessage(pKIRequestMessage, errorMessage);
        failureResponseMessage.setProtectionAlgorithm(encodedProtectionAlgorithm);
        failureResponseMessage.createErrorMsgContent();
        failureResponseMessage.createPKIHeader(issuer, recipient, senderNonce, recipientNonce, transactionID);
        failureResponseMessage.createPKIBody(failureResponseMessage.getErrorMsgContent());
        if (x509Certificate != null) {
            final List<X509Certificate> extraCerts = new ArrayList<X509Certificate>();
            extraCerts.add(x509Certificate);
            failureResponseMessage.createPKIMessage(extraCerts);
        } else {
            failureResponseMessage.createPKIMessage();
        }
        return failureResponseMessage;

    }

}
