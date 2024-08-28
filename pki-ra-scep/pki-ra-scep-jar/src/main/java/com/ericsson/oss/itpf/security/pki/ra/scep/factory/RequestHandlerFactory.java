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
package com.ericsson.oss.itpf.security.pki.ra.scep.factory;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.ra.scep.api.PkiScepRequest;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.scep.constants.Operation;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.NotImplementedOperException;
import com.ericsson.oss.itpf.security.pki.ra.scep.handler.RequestHandler;
import com.ericsson.oss.itpf.security.pki.ra.scep.qualifier.RequestQualifier;

/**
 * This class returns ScepRequestHandler instance based on the operation.
 *
 * @author xtelsow
 */
public class RequestHandlerFactory {

    @Inject
    @RequestQualifier(Operation.PKIOPERATION)
    private RequestHandler pkiOperationHandler;

    @Inject
    @RequestQualifier(Operation.GETCACERT)
    private RequestHandler getCACertHandler;

    @Inject
    @RequestQualifier(Operation.GETCACERTCHAIN)
    private RequestHandler getCACertChainHandler;

    @Inject
    private Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * This method is used to get the specific Handler object based on the SCEP operation.
     *
     * @param PkiScepRequest
     *            object contains operation, message and caName.
     * @return RequestHandler is the specific handler object which is initialized based on the operation.
     * @throws InvalidOperationException
     *             This exception is thrown if the operation is not supported by SCEP draft.
     * @throws NotImplementedOperException
     *             This exception is thrown if the operation is not implemented but supported by SCEP draft.
     **/

    @Profiled
    public RequestHandler getInstance(final PkiScepRequest pkiScepRequest) throws NotImplementedOperException {
        logger.debug("getInstance method of RequestHandlerFactory");
        RequestHandler requestHandler = null;
        switch (pkiScepRequest.getOperation()) {
        case PKIOPERATION:
            requestHandler = pkiOperationHandler;
            break;
        case GETCACERT:
            requestHandler = getCACertHandler;
            break;
        case GETCACERTCHAIN:
            requestHandler = getCACertChainHandler;
            break;
        case GETNEXTCACERT:
        case GETCACAPS:
            logger.error("The Operation {} is not implemented" , pkiScepRequest.getOperation().getScepOperation());
            systemRecorder.recordSecurityEvent("PKIRASCEPService", "SCEPRequestHandlerFactory", "The Operation " + pkiScepRequest.getOperation().getScepOperation()
                    + " is not supported by the PKI RA SCEP system", "ScepRequestHandler", ErrorSeverity.NOTICE, "FAILURE");
            throw new NotImplementedOperException(ErrorMessages.OPERATION_NOT_IMPLEMENTED);
        }
        logger.debug("End of getInstance method of RequestHandlerFactory");
        return requestHandler;

    }
}
