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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.utils;

import java.io.IOException;

import javax.naming.InvalidNameException;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.*;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPResponse;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Constants;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.PKIMessageUtil;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.constants.CMPModelConstants;

/**
 * This class will build the CMPServiceResponse object.
 * 
 * 
 */

public class ResponseBuilderUtility {

    private ResponseBuilderUtility() {

    }

    /**
     * This method will build the CMPServiceResponse object based on ResponseMessage object and transactionID
     * 
     * @param pKIResponseMessage
     *            from which required parameters has to be extract to form CMPResponse.
     * @param transactionID
     *            to identify the transaction
     * @param isSyncResponse
     *            CMP response type
     * @param issuerName
     *            issuer name of the Node Certificate which is used as alias name for RA Credentials in the CMP Key Store.
     * @return The CMPServiceResponse object
     * @throws IOException
     *             is thrown if an exception occurs while performing I/O Operations
     */
    public static CMPResponse buildResponseEvent(final ResponseMessage pKIResponseMessage, final String transactionID, final boolean isSyncResponse, final String issuerName) throws IOException {

        final String entityName = pKIResponseMessage.getResponsePKIHeader().getRecipient().getName().toString();
        final byte[] cMPResposeByteArray = pKIResponseMessage.toByteArray();
        final String errorInfo = setErrorInfoBasedOnResponseType(pKIResponseMessage);
        return (new CMPResponse()).setCmpResponse(cMPResposeByteArray).setEntityName(entityName).setErrorInfo(errorInfo).setSyncResponse(isSyncResponse)
                .setProtectionAlgorithm(pKIResponseMessage.getProtectionAlgorithm().getEncoded()).setResponseType(getCMPServiceResponseType(pKIResponseMessage)).setTransactionID(transactionID)
                .setIssuerName(issuerName);

    }

    /**
     * This method will get the subject CN based on RequestMessage object
     * 
     * @param pKIRequestMessage
     *            from which subjectCN has to be fetched
     * @return entityCN
     * @throws InvalidNameException
     *             is thrown if any naming syntax error occurs.
     * 
     */
    public static String getSubjectCNfromRequest(final RequestMessage pKIRequestMessage) throws InvalidNameException {
        String entityCN = null;
        entityCN = PKIMessageUtil.getSubjectCNfromPKIMessage(pKIRequestMessage.getPKIMessage());
        return entityCN;

    }

    /**
     * This method will build the CMPServiceResponse object based on the errorMessage and transactionId
     * 
     * @param errorMessage
     *            error Message to be set to CMPResponse.
     * @param transactionId
     *            transaction Id to be set to identify the transaction
     * @param isSyncResponse
     *            CMP response type
     * @param issuerName
     *            issuer name of the Node Certificate which is used as alias name for RA Credentials in the CMP Key Store.
     * @return The CMPServiceResponse Object
     */
    public static CMPResponse buildDefaultResponseEventForUnknownError(final String errorMessage, final String transactionId, final boolean isSyncResponse, final String issuerName) {

        return (new CMPResponse()).setTransactionID(transactionId).setCmpResponse(null).setProtectionAlgorithm(null).setResponseType(Constants.UNKNOWN_ERROR_RESPONSE).setEntityName(null)
                .setErrorInfo(errorMessage).setSyncResponse(isSyncResponse).setIssuerName(issuerName);
    }

    private static int getCMPServiceResponseType(final ResponseMessage pKIResponseMessage) {

        final String messageType = pKIResponseMessage.getClass().getSimpleName();
        int responseType;

        switch (messageType) {

        case "IPResponseMessage":
            responseType = Constants.INITIALIZATION_RESPONSE;
            break;

        case "KeyUpdateResponseMessage":
            responseType = Constants.KEY_UPDATE_RESPONSE;
            break;

        case "FailureResponseMessage":
        default:
            responseType = Constants.CMP_ERRORED_RESPONSE;
            break;

        }
        return responseType;
    }

    private static String setErrorInfoBasedOnResponseType(final ResponseMessage pKIResponseMessage) {
        if (pKIResponseMessage instanceof FailureResponseMessage) {
            return ((FailureResponseMessage) pKIResponseMessage).getErrorMessage();
        } else {
            return CMPModelConstants.NO_ERROR_INFO;
        }
    }
}
