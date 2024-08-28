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

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.UnsupportedRequestTypeException;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Constants;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.qualifiers.ProtocolRequestType;

/**
 * This class implements RequestHandlerFactory. Here all the requestHandlers are declared. Any new requestHandler to be written needs to be declared here.
 * 
 * @author tcsdemi
 *
 */
public class RequestHandlerFactoryImpl implements RequestHandlerFactory {

    @ProtocolRequestType(Constants.TYPE_INIT_REQ)
    @Inject
    private RequestHandler initializationRequestHandler;

    @ProtocolRequestType(Constants.TYPE_CERT_CONF)
    @Inject
    private RequestHandler certConfRequestHandler;

    @ProtocolRequestType(Constants.TYPE_POLL_REQ)
    @Inject
    private RequestHandler pollRequestHandler;

    @ProtocolRequestType(Constants.TYPE_KEY_UPDATE_REQ)
    @Inject
    private RequestHandler keyUpdateRequestHandler;
    
    @Inject
    Logger logger;

    @Override
    public RequestHandler getRequestHandler(final RequestMessage pKIRequestMessage) throws UnsupportedRequestTypeException {

        int cMPRequestType;
        cMPRequestType = pKIRequestMessage.getRequestType();
        RequestHandler requestHandler = null;

        switch (cMPRequestType) {

        case Constants.TYPE_INIT_REQ:
            requestHandler = initializationRequestHandler;
            break;

        case Constants.TYPE_CERT_CONF:
            requestHandler = certConfRequestHandler;
            break;

        case Constants.TYPE_POLL_REQ:
            requestHandler = pollRequestHandler;
            break;

        case Constants.TYPE_KEY_UPDATE_REQ:
            requestHandler = keyUpdateRequestHandler;
            break;

        default:
            logger.error("Received unsupported/invalid request type with code: {}" , cMPRequestType);
            throw new UnsupportedRequestTypeException(ErrorMessages.UNKNOWN_MESSAGE_TYPE);


        }

        return requestHandler;
    }

}
