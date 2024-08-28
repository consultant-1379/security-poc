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
package com.ericsson.oss.itpf.security.pki.ra.scep.api;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.ra.scep.exception.*;

/**
 * This is an interface for SCEP protocol service and provides below operation.
 * <ul>
 * <li>handleRequest: handles the PKI SCEP requests</li>
 * </ul>
 *
 * @author xjagcho
 */
@EService
public interface PkiScepService {
    /**
     * This method will hand over the pkiScepRequest to corresponding OperationHandler based on the operation present in the PkiScepRequest object.
     *
     * @param PkiScepRequest
     *            object contains operation,message and caName.
     * @return PkiScepResponse object which contains contentType and response message.
     * @throws PkiScepServiceException
     *             will be thrown when an exception occurs while processing the request or building the response.
     * @throws BadRequestException
     *             will be thrown in case of invalid request.
     * @throws UnauthorizedException
     *             will be thrown in following scenarios: 1)When the OTPValidation fails. 2)Entity not found for which the certificate has to be created. 3)Invalid Entity arguments are fetched for the
     *             provided entity for certificate generation.
     * @throws NotImplementedException
     *             will be thrown when Message or operation requested from SCEP client is present in SCEP draft but not implemented .
     */

    PkiScepResponse handleRequest(final PkiScepRequest pkiScepRequest) throws PkiScepServiceException, BadRequestException, UnauthorizedException, NotImplementedException;

}
