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

package com.ericsson.itpf.security.pki.cmdhandler.ejb.impl;

import java.lang.reflect.ParameterizedType;
import java.lang.reflect.Type;
import java.util.Set;

import javax.ejb.Stateless;
import javax.enterprise.context.spi.CreationalContext;
import javax.enterprise.inject.spi.Bean;
import javax.enterprise.inject.spi.BeanManager;
import javax.enterprise.util.AnnotationLiteral;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.PkiWebCliService;
import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.types.PkiCommandType;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.parser.antlr.PkiCliCommandParser;
import com.ericsson.itpf.security.pki.cmhandler.handler.validation.PKIWebCLIValidator;
import com.ericsson.itpf.security.pki.cmhandler.handler.validation.UseValidator;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;

/**
 * Service Bean of PkiWebCliService having the implementation of PkiWebCliService.
 *
 * @author xsumnan on 29/03/2015.
 */
@Stateless
public class PkiWebCliServiceBean implements PkiWebCliService {

    @Inject
    private Logger logger;

    @Inject
    private PkiCliCommandParser commandParser;

    @Inject
    private BeanManager beanManager;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * com.ericsson.itpf.security.pki.command.mapper.PkiCliCommand it and calling processCommand(PkiPropertyCommand)
     *
     *
     * @param commandObject
     *            - the commandObject
     * @return PkiCommandResponse
     * @throws PkiWebCliException
     *             Thrown in case any command syntax error occurs.
     * @throws PkiCLIException
     *             Thrown in case of any runtime errors while parsing the command.
     *
     */
    @Override
    public PkiCommandResponse processCommand(final PkiCliCommand commandObject) throws PkiWebCliException, PkiCLIException {
        PkiPropertyCommand pkiCommand = null;
        try {
            pkiCommand = commandParser.parseCommand(commandObject);
        } catch (final CommandSyntaxException e) {

            logger.error("Starting the Validation of Pki Command: {}", commandObject.getCommandText());
            logger.error("Command syntax error: ", e);
            throw e;
        }

        return this.processCommand(pkiCommand);
    }

    private PkiPropertyCommand createExpectedCommandForHandler(final CommandHandler<?> commandHandler, final PkiPropertyCommand sourceCommand) throws InstantiationException, IllegalAccessException {
        try {
            final Class<? extends PkiPropertyCommand> expectedType = getExpectedCommandTypeForHandler(commandHandler);
            final PkiPropertyCommand newCommand = expectedType.newInstance();
            newCommand.setCommandType(sourceCommand.getCommandType());
            newCommand.setProperties(sourceCommand.getProperties());

            return newCommand;
        } catch (final InstantiationException e) {
            logger.debug(
                    "Error creating expected Property of type com.ericsson.itpf.security.pki.command.mapper.PkiPropertyCommand " + " for handler", e);
            logger.error("Error creating expected Property of type com.ericsson.itpf.security.pki.command.mapper.PkiPropertyCommand "
                    + " for handler [{}] ", commandHandler.getClass().getName());
            throw new InstantiationException();
        } catch (final IllegalAccessException e) {
            logger.error("IllegalAcccess Error creating expected Property of type com.ericsson.itpf.security.pki.command.mapper.PkiPropertyCommand "
                    + " for handler [{}]", commandHandler.getClass().getName());
            throw new IllegalAccessException();
        }
    }

    private Class<? extends PkiPropertyCommand> getExpectedCommandTypeForHandler(final CommandHandler<?> commandHandler) {
        Class<? extends PkiPropertyCommand> commandClazz = null;

        for (final Type type : commandHandler.getClass().getGenericInterfaces()) {
            if (type instanceof ParameterizedType) {
                final ParameterizedType pType = (ParameterizedType) type;
                if (pType.getRawType() instanceof Class) {
                    final Class<?> interfaceClazz = (Class<?>) pType.getRawType();
                    if (CommandHandlerInterface.class.isAssignableFrom(interfaceClazz)) {
                        commandClazz = (Class<? extends PkiPropertyCommand>) pType.getActualTypeArguments()[0];
                    }
                }
            }
        }

        if (commandClazz == null) {
            commandClazz = PkiPropertyCommand.class;
        }

        return commandClazz;
    }

    private Bean<CommandHandler> getCommandHandlerBeanForType(final PkiCommandType pkiCommandType) {
        try {
            final Set<Bean<?>> beans = beanManager.getBeans(CommandHandlerInterface.class, new CommandTypeQualifier(pkiCommandType));
            if (beans.size() == 1) {
                return (Bean<CommandHandler>) beans.iterator().next();
            } else if (beans.isEmpty()) {
                final String msg = "No CommandHandler registered for commandType " + pkiCommandType;
                logger.error(msg);
                throw new CouldNotFindCommandHandlerException(msg);
            } else {
                final String msg = "Multiple Command Handler implementation found for commandType " + pkiCommandType;
                logger.error(msg);
                throw new CouldNotFindCommandHandlerException(msg);
            }
        } catch (final CouldNotFindCommandHandlerException e) {
            throw e;
        } catch (final Exception e) {
            logger.error("Internal Error while retrieving CommandHandler for commandType [{}].", pkiCommandType);
            throw new CouldNotFindCommandHandlerException(e);
        }
    }

    private class CommandTypeQualifier extends AnnotationLiteral<CommandType> implements CommandType {

        private static final long serialVersionUID = 6834336125012984711L;
        private final PkiCommandType commandType;

        private CommandTypeQualifier(final PkiCommandType commandType) {
            this.commandType = commandType;
        }

        @Override
        public PkiCommandType value() {
            return commandType;
        }

        @Override
        public int hashCode() {
            final int prime = 31;
            int result = super.hashCode();
            result = prime * result + getOuterType().hashCode();
            result = prime * result + ((commandType == null) ? 0 : commandType.hashCode());
            return result;
        }

        @Override
        public boolean equals(final Object obj) {
            if (this == obj) {
                return true;
            }
            if (!super.equals(obj)) {
                return false;
            }
            if (getClass() != obj.getClass()) {
                return false;
            }
            final CommandTypeQualifier other = (CommandTypeQualifier) obj;
            if (!getOuterType().equals(other.getOuterType())) {
                return false;
            }
            return commandType == other.commandType;
        }

        private PkiWebCliServiceBean getOuterType() {
            return PkiWebCliServiceBean.this;
        }
    }

    private class ExecutionContext {
        private PkiPropertyCommand command;
        private CommandHandler<PkiPropertyCommand> commandHandler;

        private ExecutionContext(final PkiPropertyCommand command, final CommandHandler<PkiPropertyCommand> commandHandler) {
            this.command = command;
            this.commandHandler = commandHandler;
        }

        public PkiPropertyCommand getCommand() {
            return command;
        }

        public void setCommand(final PkiPropertyCommand command) {
            this.command = command;
        }

        public CommandHandler<PkiPropertyCommand> getCommandHandler() {
            return commandHandler;
        }

        public void setCommandHandler(final CommandHandler<PkiPropertyCommand> commandHandler) {
            this.commandHandler = commandHandler;
        }

    }

    /**
     * Method used to handle PkiPropertyCommand and delegate to corresponding handler implementation
     *
     * @throws PkiWebCliException
     *             Thrown in case any command syntax error occurs.
     * @throws PkiCLIException
     *             Thrown in case of any runtime errors while parsing the command.
     */
    @Override
    public PkiCommandResponse processCommand(final PkiPropertyCommand commandObject) throws PkiWebCliException, PkiCLIException {

        final PkiCommandType commandType = (commandObject != null) ? commandObject.getCommandType() : null;

        PkiCommandResponse response = null;

        logger.info("Starting the processing of PKI Command: {}", commandType);

        ExecutionContext executionContext = null;
        try {
            executionContext = createExecutionContexts(commandObject);

            validateCommand(executionContext);

            final PkiPropertyCommand pkiPropertyCommand = executionContext.getCommand();

            String pkiPropertyCommandResult = pkiPropertyCommand.getCommandType().toString();

            if (PkiPropertyCommand.isPkiAdmCommand(pkiPropertyCommand)) {

                logger.info("Command {} is validated sucessfully", pkiPropertyCommandResult);

            } else {
                logger.error("Command {} is an unrecognized command", pkiPropertyCommandResult);
            }

            response = executionContext.getCommandHandler().process(pkiPropertyCommand);

        } catch (final PkiWebCliException e) {

            logger.warn("Error during com.ericsson.itpf.security.pki.command execution. Re-throwing", e);
            throw e;
        } catch (final Exception e) {

            logger.error("Unexpected error during com.ericsson.itpf.security.pki.command execution." + " Throwing UnexpectedErrorException", e);
            throw new PkiCLIException(e.getMessage());
        }

        return response;

    }

    private void validateCommand(ExecutionContext executionContext) {
        final CommandHandler<PkiPropertyCommand> commandHandler = executionContext.getCommandHandler();

        if (commandHandler.getClass().isAnnotationPresent(UseValidator.class)) {
            final UseValidator validatorsAnnotation = commandHandler.getClass().getAnnotation(UseValidator.class);

            for (final Class<? extends PKIWebCLIValidator> validatorClazz : validatorsAnnotation.value()) {
                try {
                    validateCommandBean(validatorClazz, executionContext);
                } catch (final Exception e) {
                    logger.error("Error applying validator [" + validatorClazz.getSimpleName() + "] for commandType ["
                            + executionContext.getCommand().getCommandType() + "]");
                    throw new CouldNotFindCommandHandlerException(e);
                }
            }
        }
    }

    private ExecutionContext createExecutionContexts(final PkiPropertyCommand commandObject) throws InstantiationException, IllegalAccessException {

        ExecutionContext executionContext = null;
        final String commandObjectResult = commandObject.getCommandType().name();
        logger.debug("Creating Execution Contexts for command type: {}", commandObjectResult);
        final Bean<?> bean = getCommandHandlerBeanForType(commandObject.getCommandType());
        final CreationalContext<?> creationalContext = beanManager.createCreationalContext(bean);
        final CommandHandler<PkiPropertyCommand> commandHandler = (CommandHandler<PkiPropertyCommand>) beanManager.getReference(bean,
                CommandHandlerInterface.class, creationalContext);

        try {
            logger.debug("CommandHandler for com.ericsson.itpf.security.pki.command.PkiPropertyCommand type {} is {}", commandObject.getCommandType(),
                    creationalContext);

            final PkiPropertyCommand targetCommandObject = createExpectedCommandForHandler(commandHandler, commandObject);
            executionContext = new ExecutionContext(targetCommandObject, commandHandler);

            return executionContext;
        } finally {
            creationalContext.release();
        }
    }

    private void validateCommandBean(final Class<? extends PKIWebCLIValidator> validatorClazz, ExecutionContext executionContext)
    {
        final Set<Bean<?>> beans = beanManager.getBeans(validatorClazz);
        if (beans.size() == 1) {
            final Bean<?> bean = beans.iterator().next();
            final CreationalContext<?> creationalContext = beanManager.createCreationalContext(bean);
            final PKIWebCLIValidator validatorInstance = (PKIWebCLIValidator) beanManager.getReference(bean, PKIWebCLIValidator.class,
                    creationalContext);
            try {
                logger.debug("Executing validator: {}", validatorClazz.getSimpleName());
                validatorInstance.validate(executionContext.getCommand());
            } catch (final PkiWebCliException e) {
                logger.error("Error during validation of command {} ", executionContext.getCommand().getCommandType() + e.getErrorType().toString());
                logger.warn("Error during command validation. Re-throwing", e);
                throw e;
            } catch (final Exception e) {
                logger.error("Unexpected error during command validation. Throwing UnexpectedException", e);
                throw new PkiCLIException(e.getMessage());
            }
        } else if (beans.isEmpty()) {
            final String msg = "No Validator found for class " + validatorClazz.getSimpleName();
            systemRecorder.recordError("PKIWebcli Service", ErrorSeverity.ERROR, "Starting the Validation of PKI webcli Command",
                    "COMMAND.INITIAL_VALIDATION", msg);
            logger.error("Error during command validation {}", msg);
            throw new PkiCLIException(msg);
        } else {
            final String msg = "Multiple Validators found for class " + validatorClazz.getSimpleName();
            systemRecorder.recordError("PKIWebcli Service", ErrorSeverity.ERROR, "Starting the Validation of PKI webcli Command",
                    "COMMAND.INITIAL_VALIDATION", msg);
            logger.error("Error during command validation {}", msg);
            throw new PkiCLIException(msg);
        }
    }
}
