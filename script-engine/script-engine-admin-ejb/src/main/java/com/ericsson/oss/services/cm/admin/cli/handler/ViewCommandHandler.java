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

import com.ericsson.oss.itpf.sdk.config.ConfigurationEnvironment;
import com.ericsson.oss.services.cm.admin.cli.CliCommand;
import com.ericsson.oss.services.cm.admin.cli.manager.ParameterManager;
import com.ericsson.oss.services.cm.admin.cli.response.CommandResponseDtoHelper;
import com.ericsson.oss.services.cm.admin.cli.utils.FilterContext;
import com.ericsson.oss.services.cm.admin.cli.utils.ParameterValueMapper;
import com.ericsson.oss.services.cm.admin.domain.ConfigurationParameter;
import com.ericsson.oss.services.cm.admin.rest.configuration.ConfigurationParameterFilterCriteria;
import com.ericsson.oss.services.cm.admin.rest.configuration.ConfigurationService;
import com.ericsson.oss.services.cm.admin.security.Secure;
import com.ericsson.oss.services.cm.admin.utility.ConfigurationServiceHelper;
import com.ericsson.oss.services.cm.admin.utility.PasswordHelper;
import com.ericsson.oss.services.cm.error.ErrorHandlerImpl;
import com.ericsson.oss.services.scriptengine.spi.dtos.CommandResponseDto;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;

import javax.inject.Inject;
import java.util.*;
import java.util.function.Function;

import static com.ericsson.oss.services.cm.admin.security.AccessControl.APP_PARAM_VIEW;
import static com.ericsson.oss.services.cm.error.ErrorHandlerImpl.RECEIVED_NULL_MESSAGE_ERROR_CODE;
import static com.ericsson.oss.services.cm.error.ErrorHandlerImpl.PARAMETER_NOT_EXIST_ERROR_CODE;

/**
 * This class extends the {@link AbstractCommandHandler} and implements the view command handler.
 */
public class ViewCommandHandler extends AbstractCommandHandler {

    @Inject
    private ErrorHandlerImpl errorHandler;

    @Inject
    private ConfigurationEnvironment configEnvironment;

    @Inject
    private PasswordHelper passwordHelper;

    @Inject
    private ConfigurationService configurationService;

    @Inject
    private ConfigurationServiceHelper configurationServiceHelper;

    private final Function<String, String> passwordDecoder = password -> passwordHelper.decryptDecode(password);
    private final ParameterManager parmManager = new ParameterManager();
    private static final String UNKNOWN = "UNKNOWN";

    @Override
    @Secure(accessControl = APP_PARAM_VIEW)
    public CommandResponseDto processCommand(final CliCommand command) {
        return super.processCommand(command);
    }

    /**
     * Execute the input {@link CliCommand} and {@link CommandLine}, and returns a {@link CommandResponseDto} to the CLI.
     *
     * @param command
     *            the input command
     * @param commandOptions
     *            the input command options
     * @return the CLI response
     */
    @Override
    protected CommandResponseDto executeCommand(final CliCommand command, final CommandLine commandOptions) {
        String[] parameters = command.getParameters();
        CommandResponseDto responseDto = null;
        if (parameters != null) {
            if (Arrays.stream(parameters).anyMatch(cliParams -> cliParams.contains("--name"))) {
                responseDto = viewByName(commandOptions);
                logger.info("Admin command executed successfully, the command is {}.", command.getFullCommand());
            } else {
                responseDto = viewAllParms(commandOptions);
                logger.info("Admin command executed successfully, the command is {}.", command.getFullCommand());
            }
        }
        return responseDto;
    }

    private CommandResponseDto viewByName(final CommandLine commandOptions) {
        final String parmName = commandOptions.getOptionValue("name");
        final String parmValue = getParmValue(commandOptions);
        if (parmValue == null) {
            final String errorMessage = errorHandler.createErrorMessage(PARAMETER_NOT_EXIST_ERROR_CODE, "\"" + parmName + "\"");
            final String solution = errorHandler.createSolutionMessage(PARAMETER_NOT_EXIST_ERROR_CODE, "\"" + parmName + "\"");
            return CommandResponseDtoHelper.fromErrorCode(PARAMETER_NOT_EXIST_ERROR_CODE, errorMessage, solution).getResponseDto();
        } else if (UNKNOWN.equals(parmValue)) {
            final String errorMessage = errorHandler.createErrorMessage(RECEIVED_NULL_MESSAGE_ERROR_CODE);
            final String solution = errorHandler.createSolutionMessage(RECEIVED_NULL_MESSAGE_ERROR_CODE);
            return CommandResponseDtoHelper.fromErrorCode(RECEIVED_NULL_MESSAGE_ERROR_CODE, errorMessage, solution).getResponseDto();
        } else {
            final String displayParmValue = parmName + ": " + parmValue;
            return CommandResponseDtoHelper.fromMessage(displayParmValue).withCommand("admin").getResponseDto();
        }

    }

    /**
     * Get the specific options for the command.
     *
     * @return the Options.
     */
    @Override
    protected Options getCommandOptions() {
        final Options viewOptions = new Options();
        final Option viewtOption = new Option(null, "name", true, "parameter name option");
        viewtOption.setArgs(1);
        viewtOption.setRequired(false);
        viewOptions.addOption(viewtOption);

        final Option serviceIdentifierOption = new Option(null, "service_identifier", true, "service identifier option");
        serviceIdentifierOption.setArgs(1);
        serviceIdentifierOption.setRequired(false);
        viewOptions.addOption(serviceIdentifierOption);

        final Option jvmIdentifierOption = new Option(null, "app_server_identifier", true, "jvm identifier option");
        jvmIdentifierOption.setArgs(1);
        jvmIdentifierOption.setRequired(false);
        viewOptions.addOption(jvmIdentifierOption);

        final Option allOption = new Option(null, "all", false, "all matching values");
        allOption.setRequired(false);
        viewOptions.addOption(allOption);

        return viewOptions;
    }

    private String getParmValue(final CommandLine commandLine) {
        String parameterName = commandLine.getOptionValue("name");
        try {
            ConfigurationParameterFilterCriteria configurationParameterFilterCriteria = configurationServiceHelper.prepareFilterOptionsFromCliParameters(commandLine);
            String parameterValue = configurationService.getParameter(configurationParameterFilterCriteria);
            logger.info("parameterName:{} parameterValue:{}", parameterName, parameterValue);
            FilterContext filterContext = new FilterContext(parameterName, parameterValue, parmManager, passwordDecoder);
            return ParameterValueMapper.getSuitableConverter(filterContext).convert(filterContext);
        } catch (Exception exception) {
            logger.error(String.format("Error in fetching parameterName:%s, error:%s", parameterName, exception.getMessage()), exception);
            return UNKNOWN;
        }
    }

    private CommandResponseDto viewAllParms(CommandLine commandLine) {
        return CommandResponseDtoHelper.fromMessage("All parameters:")
                .withCommand("admin")
                .appendParmDataTable(getAllConfigurationPibParametersWithValues(commandLine))
                .getResponseDto();
    }

    private Collection<String[]> getAllConfigurationPibParametersWithValues(final CommandLine commandLine) {
        final List<String[]> paramCollectData = new ArrayList<>();
        ConfigurationParameterFilterCriteria filterCriteria = configurationServiceHelper.prepareFilterOptionsFromCliParameters(commandLine);
        List<ConfigurationParameter> parameters = configurationService.getAllParameter(filterCriteria);
        if (parameters != null) {
            for (ConfigurationParameter configurationParameter : parameters) {
                String name = configurationParameter.getName();
                String value = Optional.ofNullable(configurationParameter.getFirstNonNullValue())
                        .map(Object::toString).orElse(null);
                FilterContext filterContext = new FilterContext(name, value, parmManager, passwordDecoder);
                String formattedValue = ParameterValueMapper.getSuitableConverter(filterContext).convert(filterContext);
                paramCollectData.add(new String[]{name, formattedValue});
            }
        }
        return paramCollectData;
    }
}