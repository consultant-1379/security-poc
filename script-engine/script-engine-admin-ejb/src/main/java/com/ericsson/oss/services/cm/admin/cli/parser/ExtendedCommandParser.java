/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2019
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.services.cm.admin.cli.parser;

import java.util.Iterator;

import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

/**
 * Extends Apache commons CLI {@link DefaultParser} to provide custom behaviour for parsing of admin specific commands.
 */
public class ExtendedCommandParser extends DefaultParser {

    @Override
    /**
     * Parse the arguments with provided {@link Options}.
     *
     * @param commandOptions
     *            the options command supports
     * @param arguments
     *            the input command arguments
     * @return the command line
     */
    public CommandLine parse(final Options commandOptions, final String[] arguments) throws ParseException {
        final CommandLine commandLine = super.parse(commandOptions, arguments);
        if (commandLine.getArgs().length > 0) {
            throw new ParseException("Unexpected arguments in command");
        }
        final Iterator options = commandOptions.getOptions().iterator();
        while (options.hasNext()) {
            final Option option = (Option) options.next();
            if ((!"all".equals(option.getLongOpt())) &&
                    ((commandLine.getOptionValues(option.getLongOpt()) == null)
                            && (commandLine.hasOption(option.getLongOpt())))) {
                throw new ParseException("missing arguments for option " + option.getLongOpt());
            }
            if ((!"all".equals(option.getLongOpt())) &&
                    ((commandLine.getOptionValues(option.getLongOpt()) != null)
                            && (commandLine.getOptionValues(option.getLongOpt()).length > 1))) {
                throw new ParseException("multiple arguments for option " + option.getLongOpt());
            }
        }
        return commandLine;
    }
}