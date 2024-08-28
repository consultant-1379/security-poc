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
package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.response.handler;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPResponse;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.ResponseSignerException;

/**
 * This is an interface for handling response from PKI-Manager. IP/KUP or Failure responses will be sent from PKI-Manager which needs to be handled at RA side. <br>
 * Method: <code>byte[] handle(final CMPServiceResponse cMPServiceResponse)<code>. All response handlers which deal with PKI-Manager response, need to  implement this interface.
 * 
 * @author tcsdemi
 *
 */
public interface ResponseHandler {

    /**
     * This is an interface for all ResponseHandlers which will handle response which is sent from PKI-Manager. Once messages are received from PKI-Manager based on the responseType in CMPResponse
     * respective responseHandlers will handle IP/KUP/Error responses and update in DB status and the responseMessage bytes.
     * 
     * @param cMPResponse
     *            It is a modeled event which will be received over the modeled event bus which will contain responseType/ResponseBytes/TransactionId
     * @return byte[] returns actual response build at pki-Manager and sent over modeled event bus.
     * @throws ResponseSignerException
     *             is thrown if any error occurs while forming/signing response.
     */

    byte[] handle(final CMPResponse cMPResponse) throws ResponseSignerException;

}
