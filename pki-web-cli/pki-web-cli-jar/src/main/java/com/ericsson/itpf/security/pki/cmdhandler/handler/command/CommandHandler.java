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

package com.ericsson.itpf.security.pki.cmdhandler.handler.command;

import java.io.IOException;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiPropertyCommand;

/**
 * Interface for all CommandHandler implementation of type PkiPropertyCommand All the implementation classes needs to implement the process method in order to get the corresponding handler invoked
 * 
 * @author xsumnan on 29/03/2015.
 * 
 */
public interface CommandHandler<T extends PkiPropertyCommand> extends CommandHandlerInterface {

    /**
     * Actual implementation of the com.ericsson.itpf.security.pki.cmdhandler.command.
     * 
     * @param PkiPropertyCommand
     * @return PkiCommandResponse or subclass
     * @throws IOException 
     * 
     * @see com.ericsson.itpf.security.pki.cmdhandler.api.command
     */
    PkiCommandResponse process(T command) throws IOException;
}
