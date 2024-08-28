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

package com.ericsson.itpf.security.pki.cmdhandler.parser.antlr;

import java.util.Map;

import javax.enterprise.util.AnnotationLiteral;
import javax.inject.Inject;

import org.antlr.v4.runtime.*;
import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.CommandSyntaxException;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.parser.PkiLexer;
import com.ericsson.itpf.security.pki.parser.PkiParser;

/**
 * <p>
 * Implementation of PkiCliCommandParser using Antlr
 * </p>
 *
 * @author xsumnan on 29/03/2015.
 */
public class AntlrCommandParser implements PkiCliCommandParser {

    private static final int PKIADM_CMD_SIZE = PkiCommand.APP_ID.toUpperCase().length() + 1;

    @Inject
    private Logger logger;

    /**
     * Method for parsing command with respect to antlr grammar
     *
     * @param cliCommand
     * @return PkiPropertyCommand
     *
     * @throws PkiWebCliException
     *             Thrown in case any command syntax error occurs.
     */
    @Override
    public PkiPropertyCommand parseCommand(final PkiCliCommand cliCommand) throws PkiWebCliException {
        final String commandString = cliCommand.getCommandText();

        try {

            final PkiParser.ParseCommandContext parsedCommand = parseCommand(commandString);

            final Map<String, Object> commandParseResult = parsedCommand.attributes;

            final PkiPropertyCommand PkiCommand = new PkiPropertyCommand();

            PkiCommand.setCommandType(PkiCommandType.valueOf((String) commandParseResult.get(PkiPropertyCommand.COMMAND_TYPE_PROPERTY)));

            if (cliCommand.getProperties() != null) {
                PkiCommand.getProperties().putAll(cliCommand.getProperties());
            }
            PkiCommand.getProperties().putAll(commandParseResult);

            return PkiCommand;

        } catch (final PkiWebCliException e) {
            logger.debug("Caught PkiServiceException during parsing of the user com.ericsson.itpf.security.pki.command: Syntax error.", e);
            throw e;
        } catch (final Exception e) {
            logger.info("Caught Exception during parsing of the user com.ericsson.itpf.security.pki.command: Syntax error.", e);
            throw new CommandSyntaxException(e);
        }
    }

    private PkiParser.ParseCommandContext parseCommand(final String toParse) throws CommandSyntaxException {
        final ANTLRInputStream antlrInputStream = new ANTLRInputStream(toParse);

        PkiParser pkiCommandParser = null;

        final PkiLexer lexer = new PkiLexer(antlrInputStream);
        lexer.removeErrorListeners();
        lexer.addErrorListener(new ErrorListener(PKIADM_CMD_SIZE));

        final CommonTokenStream tokens = new CommonTokenStream(lexer);
        pkiCommandParser = new PkiParser(tokens);
        pkiCommandParser.removeErrorListeners();
        pkiCommandParser.addErrorListener(new ErrorListener(PKIADM_CMD_SIZE));

        final PkiParser.ParseCommandContext context = pkiCommandParser.parseCommand();

        if (pkiCommandParser.getNumberOfSyntaxErrors() > 0) {
            logger.debug("Caught exception during parsing of the user com.ericsson.itpf.security.pki.cmdhandler.handler.command: number of errors are {}", pkiCommandParser.getNumberOfSyntaxErrors());
            throw new CommandSyntaxException();
        }

        return context;
    }

    static class ErrorListener extends BaseErrorListener {

        private int positionOffset = 0;

        ErrorListener() {
        }

        private ErrorListener(final int positionOffset) {
            this.positionOffset = positionOffset;
        }

        @Override
        public void syntaxError(final Recognizer<?, ?> recognizer, final Object offendingSymbol, final int line, final int charPositionInLine, final String msg, final RecognitionException e)
                throws CommandSyntaxException {
            throw new CommandSyntaxException();
        }
    }

    private class FileAttributeNameQualifier extends AnnotationLiteral<FileAttributeName> implements FileAttributeName {

        private static final long serialVersionUID = 809622923486134210L;
        private final String value;

        private FileAttributeNameQualifier(final String value) {
            this.value = value;
        }

        @Override
        public String value() {
            return this.value;
        }

        /*
         * (non-Javadoc)
         *
         * @see java.lang.Object#hashCode()
         */
        @Override
        public int hashCode() {
            final int prime = 31;
            int result = super.hashCode();
            result = prime * result + getOuterType().hashCode();
            result = prime * result + ((value == null) ? 0 : value.hashCode());
            return result;
        }

        /*
         * (non-Javadoc)
         *
         * @see java.lang.Object#equals(java.lang.Object)
         */
        @Override
        public boolean equals(Object obj) {
            if (this == obj) {
                return true;
            }
            if (!super.equals(obj)) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final FileAttributeNameQualifier other = (FileAttributeNameQualifier) obj;
            if (!getOuterType().equals(other.getOuterType())) {
                return false;
            }
            if (value == null) {
                if (other.value != null) {
                    return false;
                }
            } else if (!value.equals(other.value)) {
                return false;
            }
            return true;
        }

        private AntlrCommandParser getOuterType() {
            return AntlrCommandParser.this;
        }
    }

    /* (non-Javadoc)
     * @see java.lang.Object#hashCode()
     */
    @Override
    public int hashCode() {
        final int prime = 31;
        int result = 1;
        result = prime * result + ((logger == null) ? 0 : logger.hashCode());
        return result;
     }

    /*
     * (non-Javadoc)
     *
     * @see java.lang.Object#equals(java.lang.Object)
     */
     @Override
     public boolean equals(final Object obj) {
         if (this == obj) {
            return true;
        }
         if (obj == null) {
            return false;
        }
        if (getClass() != obj.getClass()) {
            return false;
        }
        final AntlrCommandParser other = (AntlrCommandParser) obj;
        if (logger == null) {
            if (other.logger != null) {
            return false;
            }
        } else if (!logger.equals(other.logger)) {
            return false;
        }
        return true;
      }
}
