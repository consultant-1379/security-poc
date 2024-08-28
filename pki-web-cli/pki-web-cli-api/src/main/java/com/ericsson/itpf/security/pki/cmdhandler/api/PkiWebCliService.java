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

package com.ericsson.itpf.security.pki.cmdhandler.api;

import javax.ejb.Remote;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException;
import com.ericsson.oss.itpf.sdk.core.annotation.EService;

/**
 * The main interface to do processing of web-cli commands
 * 
 * @author xsumnan on 29/03/2015.
 */

@EService
@Remote
public interface PkiWebCliService {
    /**
     * The following method is responsible for start execution of PKI-WebCli Commands with specified parameter
     * 
     * @param PkiCliCommand
     *            - the commandObject
     * @return PkiCommandResponse
     * @throws - PkiServiceException
     * 
     */
    PkiCommandResponse processCommand(PkiCliCommand commandObject) throws PkiWebCliException;

    /**
     * The following method is responsible for start execution of PKI-WebCli Commands with specified parameter
     * 
     * @param PkiPropertyCommand
     *            - the commandObject
     * @return - PkiCommandResponse
     * @throws - PkiServiceException
     */
    PkiCommandResponse processCommand(PkiPropertyCommand commandObject) throws PkiWebCliException;
}