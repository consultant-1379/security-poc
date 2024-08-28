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
package com.ericsson.itpf.security.pki.cmhandler.handler.validation;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException;

/**
 * Interface that defines a command validator. A PkiWebCLIValidator is responsible for performing any kind of validation or pre-condition check before the PkiWebCLICmdHandler execution.
 *
 * Ideally a validator is created whenever there is a common check that needs to be performed by more than one command.
 *
 * PkiWebCLICmdHandlers can declare what validations are required by the use of the {@literal @}UseValidator annotation
 *
 * @author DespicableUs
 */
public interface PKIWebCLIValidator {

    /**
     * Perform command validation.
     *
     * @param command
     *            PkiCmdHandlerPropertyCommand instance
     * @param context
     *            current command execution context
     * @throws WebCliServiceException
     */
    void validate(PkiPropertyCommand command) throws PkiWebCliException;

}
