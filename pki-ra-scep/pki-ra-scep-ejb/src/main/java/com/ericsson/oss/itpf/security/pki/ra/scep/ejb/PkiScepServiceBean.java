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
package com.ericsson.oss.itpf.security.pki.ra.scep.ejb;

import java.security.Security;

import javax.ejb.Stateless;
import javax.inject.Inject;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.security.pki.ra.scep.api.*;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.*;
import com.ericsson.oss.itpf.security.pki.ra.scep.factory.RequestHandlerFactory;
import com.ericsson.oss.itpf.security.pki.ra.scep.handler.RequestHandler;

/**
 * ScepServiceBean-This bean class fetches the instance of RequestHandler from RequestHandlerFactory for the corresponding operation. The request is then forwarded to the corresponding requesthandler
 * class for further processing.
 * 
 *
 * @author xtelsow
 */
@Stateless
public class PkiScepServiceBean implements PkiScepService {
    @Inject
    Logger logger;
    @Inject
    private RequestHandlerFactory reqHandlerFactory;
    @Inject
    private PkiScepResponse pkiScepResponse;

    /**
     * This static block is to add BouncyCastle Provider to the java Security.
     */
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    /**
     * This method will hand over pkiScepRequest to corresponding OperationHandler based on the operation present in the PkiScepRequest object. The OperationHandler class processes the pkiScepRequest
     * and returns the appropriate pkiScepResponse.
     *
     * @param PkiScepRequest
     *            object contains operation,message and caName.
     * @return PkiScepResponse object which contains contentType and ResponseMessage.
     * 
     * @throws BadRequestException
     *             will be thrown in case of invalid request.
     * @throws PkiScepServiceException
     *             is thrown if any exception is raised while processing the Request message or building Response message.
     * @throws NotImplementedException
     *             will be thrown when Message Type or Operation requested from SCEP client is supported by in SCEP draft but not implemented .
     * @throws UnauthorizedException
     *             will be thrown in case of when the given PKCSReq message does not have proper entity information.
     */
    @Profiled
    @Override
    public PkiScepResponse handleRequest(final PkiScepRequest pkiScepRequest) throws PkiScepServiceException, BadRequestException, UnauthorizedException, NotImplementedException {
        final RequestHandler requestHandler = reqHandlerFactory.getInstance(pkiScepRequest);
        pkiScepResponse = requestHandler.handle(pkiScepRequest);
        return pkiScepResponse;
    }
}
