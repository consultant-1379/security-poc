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

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPResponse;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Constants;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.exception.ResponseHandlerException;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.qualifiers.ProtocolResponseType;

/**
 * This class implements <code>ResponseHandlerFactory</code>. All responseHandlers which deal with PKI-Manager are declared here and based on <code>ResponseType</code> (EDT from pki-ra-cmp model)
 * responseHandler instance is returned.
 * 
 * @author tcsdemi
 *
 */
public class ResponseHandlerFactoryImpl implements ResponseHandlerFactory {

    @Inject
    Logger logger;

    @ProtocolResponseType(Constants.TYPE_INIT_RESPONSE)
    @Inject
    private ResponseHandler initializationResponseHandler;

    @ProtocolResponseType(Constants.TYPE_KEY_UPDATE_RESPONSE)
    @Inject
    private ResponseHandler keyUpdateResponseHandler;

    @ProtocolResponseType(Constants.TYPE_ERROR_RESPONSE)
    @Inject
    private ResponseHandler managerCMPErrorResponseHandler;

    @Override
    public ResponseHandler getResponseHandler(final CMPResponse cMPResponse) throws ResponseHandlerException {

        ResponseHandler responseHandler = null;

        switch (cMPResponse.getResponseType()) {
        case Constants.INITIALIZATION_RESPONSE:
            responseHandler = initializationResponseHandler;
            break;

        case Constants.KEY_UPDATE_RESPONSE:
            responseHandler = keyUpdateResponseHandler;
            break;

        case Constants.CMP_ERRORED_RESPONSE:
            responseHandler = managerCMPErrorResponseHandler;
            break;

        case Constants.UNKNOWN_ERROR_RESPONSE:
        default:
            throw new ResponseHandlerException(ErrorMessages.UNKNOWN_RESPONSE_TYPE);

        }

        return responseHandler;
    }
}
