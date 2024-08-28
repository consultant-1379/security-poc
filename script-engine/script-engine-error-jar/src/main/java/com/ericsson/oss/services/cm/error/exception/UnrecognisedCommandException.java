package com.ericsson.oss.services.cm.error.exception;

import com.ericsson.oss.services.scriptengine.spi.dtos.Command;

/**
 * UnrecognisedCommandException when no Channel or Service can be found for the command set.
 */
public class UnrecognisedCommandException extends RuntimeException {

    private static final long serialVersionUID = -8275202059039748342L;
    private final Command command;

    public UnrecognisedCommandException(final Command command) {
        super(String.format("The command set %s has no identifiable command handler queue or service available.", command.getCommandContext()));
        this.command = command;
    }

    public Command getCommand() {
        return command;
    }
}
