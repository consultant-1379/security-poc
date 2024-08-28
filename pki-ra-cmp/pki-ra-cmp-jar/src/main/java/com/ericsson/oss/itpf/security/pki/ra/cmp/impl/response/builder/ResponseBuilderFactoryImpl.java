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

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.Constants;
import com.ericsson.oss.itpf.security.pki.ra.cmp.common.qualifiers.ProtocolResponseType;

/**
 * This class implements <code>ResponseBuilderFactory</code>. All ResponseBuilders are declared here. In case of any new responseBuilder for new Requesttype then this class should have its
 * declaration.
 *
 * @author tcsdemi
 *
 */
public class ResponseBuilderFactoryImpl implements ResponseBuilderFactory {

    @Inject
    Logger logger;

    @Inject
    @ProtocolResponseType(Constants.TYPE_INIT_RESPONSE_WAIT)
    ResponseBuilder ipWithWaitResponseBuilder;

    @Inject
    @ProtocolResponseType(Constants.TYPE_KU_RESPONSE_WAIT)
    ResponseBuilder keyUpdateWithWaitResponseBuilder;

    @Inject
    @ProtocolResponseType(Constants.TYPE_PKI_CONF)
    ResponseBuilder pkiConfResponseBuilder;

    @Inject
    @ProtocolResponseType(Constants.TYPE_POLL_RESPONSE)
    ResponseBuilder pollResponseBuilder;

    @Override
    public ResponseBuilder getResponseBuilder(final RequestMessage pKIRequestMessage) {

        int requestType = 0;
        ResponseBuilder responseBuilder = null;
        requestType = pKIRequestMessage.getRequestType();

        switch (requestType) {

        case Constants.TYPE_INIT_REQ:
            responseBuilder = ipWithWaitResponseBuilder;
            break;

        case Constants.TYPE_KEY_UPDATE_REQ:
            responseBuilder = keyUpdateWithWaitResponseBuilder;
            break;

        case Constants.TYPE_POLL_REQ:
            responseBuilder = pollResponseBuilder;
            break;

        case Constants.TYPE_CERT_CONF:
            responseBuilder = pkiConfResponseBuilder;
            break;
        default:
            logger.error("Unknown request type: {}", requestType);
        }
        return responseBuilder;
    }

}
