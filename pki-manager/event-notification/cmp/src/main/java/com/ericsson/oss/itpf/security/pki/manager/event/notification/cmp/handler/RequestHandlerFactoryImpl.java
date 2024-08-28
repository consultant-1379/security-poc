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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.data.CMPRequest;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Constants;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.er.ErrorRequestHandler;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.ir.InitializationRequestHandler;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.cmp.handler.kur.KeyUpdateRequestHandler;

/**
 * This class is used to generate the type of the request handler that need to be used to generate the CMPResponse dependending upon the request.
 * 
 * @author tcschdy
 * 
 */
public class RequestHandlerFactoryImpl implements RequestHandlerFactory {

    @Inject
    InitializationRequestHandler initializationRequestHandler;

    @Inject
    KeyUpdateRequestHandler keyUpdateRequestHandler;

    @Inject
    ErrorRequestHandler errorRequestHandler;

    @Inject
    Logger logger;

    @Override
    public RequestHandler getRequestHandler(final CMPRequest cMPRequest) {
        RequestHandler protocolRequestHandler;

        switch (cMPRequest.getRequestType()) {
        case Constants.TYPE_INIT_REQ: {
            protocolRequestHandler = initializationRequestHandler;
            break;
        }
        case Constants.TYPE_KEY_UPDATE_REQ: {
            protocolRequestHandler = keyUpdateRequestHandler;
            break;
        }
        default: {
            protocolRequestHandler = errorRequestHandler;
            break;
        }

        }
        return protocolRequestHandler;
    }
}
