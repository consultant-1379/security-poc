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
package com.ericsson.oss.itpf.security.pki.ra.cmp.impl.request;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;

/**
 * This is a factory class which will have method to return appropriate requestHandlers based on RequestMessage. Method: <code> getRequestHandler(RequestMessage pKIRequestMessage)</code> will return
 * corresponding requestHandler.
 * 
 * @author tcsdemi
 *
 */
public interface RequestHandlerFactory {
    /**
     * This method will return the required instance of requestHandler based on the RequestType which is present requestMessage.
     * 
     * @param pKIRequestMessage
     * @return RequestHandler <br>
     *         Any instance of class which implements RequestHandler.
     *         <p>
     *         Note: Please refer to RequestHandler class, Method:<code> handle(RequestMessage pKIRequestmessage)</code>
     */
    RequestHandler getRequestHandler(RequestMessage pKIRequestMessage);

}
