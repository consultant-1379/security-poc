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
package com.ericsson.oss.itpf.security.pki.ra.scep.handler;

import com.ericsson.oss.itpf.security.pki.ra.scep.api.PkiScepRequest;
import com.ericsson.oss.itpf.security.pki.ra.scep.api.PkiScepResponse;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.*;

/**
 * This interface is implemented by request handlers. Based on the operation type respective handlers handle the SCEP request and calls the appropriate builder methods to build the response.
 *
 * @author xtelsow
 */
public interface RequestHandler {
    /**
     * This method is implemented by the handlers. Based on the operation type The handlers handle the SCEP request and calls the appropriate builder methods to build the responses.
     *
     * @param PkiScepRequest
     *            object contains operation,message and caName.
     * @return PkiScepResponse object which contains contentType and ResponseMessage.
     * @throws BadRequestException
     *             will be thrown in case of invalid response or if the alias name from the SCEP client is invalid.
     * @throws UnauthorizedException
     *             will be thrown in case of when the given PKCSReq message does not have proper entity information.
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     */
    PkiScepResponse handle(final PkiScepRequest pkiScepRequest) throws BadRequestException, UnauthorizedException, PkiScepServiceException;
}
