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

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.FailureResponseMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPRequest;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPResponse;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.DigitalSigningFailedException;
import com.ericsson.oss.itpf.security.pki.common.util.xml.exception.MarshalException;
import com.ericsson.oss.itpf.security.pki.credentialsmanagement.exception.CredentialsManagementServiceException;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.RequestHandler;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.utils.ResponseBuilderUtility;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.utils.SignedResponseBuilder;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.publisher.CMPServiceResponsePublisher;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.events.SignedCMPServiceResponse;

/**
 * This class is used for generating the CMP Error Response in the case where the CMPRequest is not of type Initial Request/Key Update Request and dispatching it to the CMP Service.
 * 
 * @author tcschdy
 * 
 */
public class ErrorRequestHandler implements RequestHandler {

    @Inject
    Logger logger;

    @Inject
    ErrorResponseBuilder failureResponseBuilder;

    @Inject
    CMPServiceResponsePublisher cMPServiceResponsePublisher;

    @Inject
    SignedResponseBuilder signedResponseBuilder;

    @Inject
    SystemRecorder systemRecorder;

    @Override
    public void handle(final CMPRequest cMPRequest) throws CredentialsManagementServiceException, DigitalSigningFailedException, MarshalException {
        final String errorMessage = ErrorMessages.UNKNOWN_MESSAGE_TYPE;
        final String transactionId = cMPRequest.getTransactionId();
        final boolean isSyncRequest = cMPRequest.getSyncRequest();
        CMPResponse cMPResponse = null;

        byte[] signedXMLData = null;

        logger.warn("RequestMessage from RA to Manager is neither IR nor KUR, hence an error message will be sent back to RA for the transactionID : {}", transactionId);
        try {
            final RequestMessage pKIRequestMessage = new RequestMessage(cMPRequest.getCmpRequest());

            final FailureResponseMessage failureResponseMessage = failureResponseBuilder.build(errorMessage, transactionId, pKIRequestMessage, null);
            cMPResponse = ResponseBuilderUtility.buildResponseEvent(failureResponseMessage, transactionId, isSyncRequest, cMPRequest.getIssuerName());
            signedXMLData = signedResponseBuilder.buildSignedCMPResponse(cMPResponse);
            logger.info("Built Error Message and dispatched onto the queue with senderName:{} and transactionId:{}", pKIRequestMessage.getSenderName(), pKIRequestMessage.getBase64TransactionID());

        } catch (IOException exception) {
            logger.warn("Unable to parse bytes sent from Queue for CMPService for TransactionId : {} ", cMPRequest.getTransactionId());
            logger.debug("Exception StackTrace: ", exception);
            cMPResponse = ResponseBuilderUtility.buildDefaultResponseEventForUnknownError(errorMessage, transactionId, isSyncRequest, cMPRequest.getIssuerName());
            signedXMLData = signedResponseBuilder.buildSignedCMPResponse(cMPResponse);
        }
        final SignedCMPServiceResponse signedCMPServiceResponse = new SignedCMPServiceResponse();
        if (signedXMLData != null) {
            signedCMPServiceResponse.setCmpResponse(signedXMLData);
            cMPServiceResponsePublisher.publish(signedCMPServiceResponse);
        }

    }
}
