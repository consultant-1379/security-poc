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
package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.builder;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.ra.cmp.api.exception.ResponseBuilderException;

/**
 * 
 * <p>
 * All the responsebuilders needs to explicitly build body of the PKiMessage
 * based on the request received.
 * <p>
 * Responses are:<br>
 * 1. Initialization response/Key update response<br>
 * 2.Polling response<br>
 * 3.PKIConf response<br>
 * For each of the above response data structure will be different
 * 
 * @author tcsdemi
 */
public interface ResponseBuilder {

    /**
     * This is an interface which needs to be implemented by all response
     * builders. Response builder will be implemented by Polling/Waiting/PKIConf
     * responses. Once message is build status/signed responseMessage needs to
     * be updated in DB against transactionID provided.
     * 
     * 
     * @param pKIRequestMessage
     * @param transactionId
     * @return byte[] signedResponse which will be sent back to entity
     * @throws ResponseBuilderException
     *             Thrown in case there are any exceptions which needs to be
     *             wrapped. Hence a custom Exception ResponseBuilderException is
     *             thrown
     */
    byte[] build(RequestMessage pKIRequestMessage, String transactionId) throws ResponseBuilderException;

}
