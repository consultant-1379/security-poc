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
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.ResponseHandlerException;

/**
 * This is an interface which returns responseHandler based on <code>CMPServiceResponse</code>.
 * 
 * @author tcsdemi
 *
 */
public interface ResponseHandlerFactory {

    /**
     * This is a factor class which will fetch corresponding responseHandler based on the serviceResponse received from PKI-Manager
     * 
     * @param cMPResponse
     *            It is a modeled event which will be received over the modeled event bus which will contain responseType/ResponseBytes/TransactionId
     * @return instance of ResponseHandler
     * @throws ResponseHandlerException
     *             This exception is thrown in case responseType within the event is either null or corrupted or is not either of IP/KUP/Error
     */
    ResponseHandler getResponseHandler(CMPResponse cMPResponse) throws ResponseHandlerException;

}
