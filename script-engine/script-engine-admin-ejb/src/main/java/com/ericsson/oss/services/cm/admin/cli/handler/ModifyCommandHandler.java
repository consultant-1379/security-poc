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
package com.ericsson.oss.services.cm.admin.cli.handler;

import static com.ericsson.oss.services.cm.admin.security.AccessControl.APP_PARAM_UPDATE;
import static com.ericsson.oss.services.cm.error.ErrorHandlerImpl.PARAMETER_UPDATE_FAILURE_ERROR_CODE;
import static com.ericsson.oss.services.cm.error.ErrorHandlerImpl.PARAMETER_VALUE_INVALID_ERROR_CODE;

import javax.inject.Inject;

import com.ericsson.oss.services.cm.admin.domain.ConfigurationParameter;
import com.ericsson.oss.services.cm.admin.utility.ConfigurationServiceHelper;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

import com.ericsson.oss.services.cm.admin.cli.CliCommand;
import com.ericsson.oss.services.cm.admin.cli.manager.ParameterManager;
import com.ericsson.oss.services.cm.admin.cli.response.CommandResponseDtoHelper;
import com.ericsson.oss.services.cm.admin.domain.Messages;
import com.ericsson.oss.services.cm.admin.rest.configuration.ConfigurationService;
import com.ericsson.oss.services.cm.admin.security.Secure;
import com.ericsson.oss.services.cm.admin.validation.ValidationResult;
import com.ericsson.oss.services.cm.error.ErrorHandlerImpl;
import com.ericsson.oss.services.scriptengine.spi.dtos.CommandResponseDto;

public class ModifyCommandHandler extends AbstractCommandHandler {

    @Inject
    private ConfigurationService configurationService;

    @Inject
    private ErrorHandlerImpl errorHandler;

    @Inject
    private ParameterManager paramManager;

    @Inject
    private ConfigurationServiceHelper configurationServiceHelper;

    @Override
    @Secure(accessControl = APP_PARAM_UPDATE)
    public CommandResponseDto processCommand(final CliCommand command) {
        return super.processCommand(command);
    }

    @Override
    protected CommandResponseDto executeCommand(CliCommand command, CommandLine commandOptions) {
        try {
            final String paramName = commandOptions.getOptionValue("name");
            final String paramValue = commandOptions.getOptionValue("value");

            final ValidationResult result = paramManager.paramValidation(paramName, paramValue);
            if (result.isNotValid()) {
                final String errorMessage = errorHandler.createErrorMessage(PARAMETER_VALUE_INVALID_ERROR_CODE, "\"" + paramName + "\"",
                        result.getErrorMessage());
                final String solution = errorHandler.createSolutionMessage(PARAMETER_VALUE_INVALID_ERROR_CODE);
                return CommandResponseDtoHelper.fromErrorCode(PARAMETER_VALUE_INVALID_ERROR_CODE, errorMessage, solution).getResponseDto();
            }

            ConfigurationParameter configurationParameter =
                    configurationServiceHelper.prepareConfigurationParameterFromCliParameters(commandOptions, result);
            if (configurationService.updateParameter(configurationParameter)) {
                return CommandResponseDtoHelper.fromMessage(Messages.UPDATE_PARAMETER_SUCCESS.format(paramName))
                        .withCommand("admin").getResponseDto();
            } else {
                final String errorMessage = errorHandler.createErrorMessage(PARAMETER_UPDATE_FAILURE_ERROR_CODE, "\"" + paramName + "\"");
                final String solution = errorHandler.createSolutionMessage(PARAMETER_UPDATE_FAILURE_ERROR_CODE);
                return CommandResponseDtoHelper.fromErrorCode(PARAMETER_UPDATE_FAILURE_ERROR_CODE, errorMessage, solution).getResponseDto();
            }
        } catch (final Exception e) {
            logger.warn("The exception is {}, caused by {}", e.toString(), e.getCause());
            final String errorMessage = errorHandler.createErrorMessage(PARAMETER_UPDATE_FAILURE_ERROR_CODE,
                    "\"" + commandOptions.getOptionValue("name") + "\"");
            final String solution = errorHandler.createSolutionMessage(PARAMETER_UPDATE_FAILURE_ERROR_CODE);
            return CommandResponseDtoHelper.fromErrorCode(PARAMETER_UPDATE_FAILURE_ERROR_CODE, errorMessage, solution).getResponseDto();
        }
    }

    @Override
    protected Options getCommandOptions() {

        final Options modifyOptions = new Options();

        final Option nameOption = new Option(null, "name", true, "parameter name option");
        nameOption.setArgs(1);
        nameOption.setRequired(true);
        modifyOptions.addOption(nameOption);

        final Option valueOption = new Option(null, "value", true, "parameter value option");
        valueOption.setArgs(1);
        valueOption.setRequired(true);
        modifyOptions.addOption(valueOption);

        final Option serviceIdentifierOption = new Option(null, "service_identifier", true, "service identifier option");
        serviceIdentifierOption.setArgs(1);
        serviceIdentifierOption.setRequired(false);
        modifyOptions.addOption(serviceIdentifierOption);

        final Option jvmIdentifierOption = new Option(null, "app_server_identifier", true, "jvm identifier option");
        jvmIdentifierOption.setArgs(1);
        jvmIdentifierOption.setRequired(false);
        modifyOptions.addOption(jvmIdentifierOption);

        return modifyOptions;
    }

}