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
package com.ericsson.oss.itpf.security.pki.ra.cmp.validator;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.exception.ValidationException;

/**
 * This is an interface which defines a request validator. Any new validator for the <code>RequestMessage</code> should implement this interface.
 * 
 * @author tcsdemi
 *
 */
public interface RequestValidator {
    /**
     * Interface that defines a request validator.
     * <p>
     * A RequestValidator is responsible for performing any kind of validation or pre-condition check before the request is actually executed
     * </p>
     * 
     * <p>
     * Ideally a validator is created whenever there is a common check that needs to be performed by more than one request.
     * </p>
     * 
     * <p>
     * RequestHandlers can declare what validations are required by the use of the {@literal @}UseValidator annotation
     * </p>
     * 
     * <p>
     * Example:
     * </p>
     * 
     * <code><pre>
     *      {@literal @}RequestType(ModelConstant.TYPE_INIT_REQ )
     *      {@literal @}UseValidator(InitializationRequestValidator.class)
     *      public class InitializationRequestHandler implements RequestHandler {
     * 
     *          public String handleMessage(RequestMessage pKIRequestmessage) {
     *                // Handler implementation...
     *          }
     *      }
     * </pre></code>
     * 
     * 
     * @author xdeemin
     */

    void validate(RequestMessage pKIRequestMessage) throws ValidationException;

}
