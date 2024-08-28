/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.services.cm.error;

import java.text.MessageFormat;
import java.util.HashMap;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import java.io.PrintWriter;
import java.io.StringWriter;

public class ErrorHandlerImpl {
    private static final Logger LOGGER = LoggerFactory.getLogger(ErrorHandlerImpl.class);

    public static final int UNEXPECTED_ERROR = -2;
    public static final int ERROR_CODE_UNEXPECTED_ERROR = 9999;

    public static final String EXCEPTION_MESSAGE = "Internal Error : ";

    private static Map<Integer, String[]> errorMessages = new HashMap<>();
    private static final int ERROR_MESSAGE_INDEX = 0;
    private static final int SOLUTION_MESSAGE_INDEX = 1;

    public static final int UNRECOGNISED_CLI_COMMAND_CODE = 6001;
    protected static final String[] UNRECOGNISED_CLI_COMMAND_MSGS = { "Unrecognized CLI command \"{0}\"",
            "Please check the online help for valid CLI commands" };

    public static final int ALIAS_INVALID_CREATE_ERROR_CODE = 6003;
    protected static final String[] ALIAS_INVALID_CREATE_ERROR_MSGS = {
        "Invalid alias command specification",
    "The number of arguments in the alias must match the number of arguments in the aliased command. Arguments must be unique and sequential in the range of $1 to $9" };
    public static final int ALIAS_ALREADY_EXISTS_ERROR_CODE = 6004;
    protected static final String[] ALIAS_ALREADY_EXISTS_ERROR_MSGS = { "Alias with name \"{0}\" already exists", "Create an alias with an unique name" };

    public static final int ALIAS_SYNTAX_ERROR_CODE = 6006;
    protected static final String[] ALIAS_SYNTAX_ERROR_MSGS = { "Invalid alias command syntax", "Please check online help for correct syntax" };

    public static final int RECEIVED_NULL_MESSAGE_ERROR_CODE = 6010;
    protected static final String[] RECEIVED_NULL_MESSAGE_ERROR_MSGS = { "Received an invalid response which could not be processed",
    "Verify if the command was successfully completed, if the problem persists contact system administrator" };
    public static final int ALIAS_INVALID_CREATE_WITH_FILE_ERROR_CODE = 6011;
    protected static final String[] ALIAS_INVALID_CREATE_WITH_FILE_ERROR_MSGS = { "Syntax Error - Commands with file input syntax cannot be aliased",
            "" };
    public static final int ALIAS_INVALID_CREATE_WITH_COMMAND_SET_ERROR_CODE = 6012;
    protected static final String[] ALIAS_INVALID_CREATE_WITH_COMMAND_SET_ERROR_MSGS = { "Cannot create alias with name \"{0}\" as it is a CLI Command Set",
            "" };
    public static final int DATABASE_NOT_AVAILABLE_ERROR_CODE = 6013;
    protected static final String[] DATABASE_NOT_AVAILABLE_ERROR_MSGS = {"Service is currently unavailable. Please try again later or contact your System Administrator.", ""};
    public static final int SYNTAX_ERROR_CODE = 6014;
    protected static final String[] SYNTAX_ERROR_MSGS = { "Command syntax error",
            "For correct command syntax please run \"help {0}\"" };

    public static final int PARAMETER_NOT_EXIST_ERROR_CODE = 6015;
    protected static final String[] PARAMETER_NOT_EXIST_ERROR_MSGS = { "Parameter {0} not exist.", "Provide a valid parameter name." };

    public static final int PARAMETER_VALUE_INVALID_ERROR_CODE = 6016;
    protected static final String[] PARAMETER_VALUE_INVALID_ERROR_MSGS = { "Invalid parameter value for Parameter {0} . {1}",
            "Provide a valid parameter value." };

    public static final int PARAMETER_UPDATE_FAILURE_ERROR_CODE = 6017;
    protected static final String[] PARAMETER_UPDATE_FAILURE_ERROR_MSGS = { "Update Parameter {0} failed.",
            "Please try again. If the problem persists contact system administrator" };
    public static final int ACCESS_UNAUTHORIZED_ERROR_CODE = 6018;
    protected static final String[] ACCESS_UNAUTHORIZED_ERROR_MSGS = { "Insufficient access rights to perform the operation.",
            "If the operation is required to be performed by current user, the user profile must be updated by the system administrator." };

    //TODO EEITSIK 6000 Error codes reserved for Script-Engine. Introduce new error codes for command-line-interface.
    static {
        errorMessages.put(UNRECOGNISED_CLI_COMMAND_CODE, UNRECOGNISED_CLI_COMMAND_MSGS);
        errorMessages.put(ALIAS_INVALID_CREATE_ERROR_CODE, ALIAS_INVALID_CREATE_ERROR_MSGS);
        errorMessages.put(ALIAS_ALREADY_EXISTS_ERROR_CODE, ALIAS_ALREADY_EXISTS_ERROR_MSGS);
        errorMessages.put(ALIAS_SYNTAX_ERROR_CODE, ALIAS_SYNTAX_ERROR_MSGS);
        errorMessages.put(RECEIVED_NULL_MESSAGE_ERROR_CODE, RECEIVED_NULL_MESSAGE_ERROR_MSGS);
        errorMessages.put(ALIAS_INVALID_CREATE_WITH_FILE_ERROR_CODE, ALIAS_INVALID_CREATE_WITH_FILE_ERROR_MSGS);
        errorMessages.put(ALIAS_INVALID_CREATE_WITH_COMMAND_SET_ERROR_CODE, ALIAS_INVALID_CREATE_WITH_COMMAND_SET_ERROR_MSGS);
        errorMessages.put(DATABASE_NOT_AVAILABLE_ERROR_CODE, DATABASE_NOT_AVAILABLE_ERROR_MSGS);
        errorMessages.put(SYNTAX_ERROR_CODE, SYNTAX_ERROR_MSGS);
        errorMessages.put(PARAMETER_NOT_EXIST_ERROR_CODE, PARAMETER_NOT_EXIST_ERROR_MSGS);
        errorMessages.put(PARAMETER_VALUE_INVALID_ERROR_CODE, PARAMETER_VALUE_INVALID_ERROR_MSGS);
        errorMessages.put(PARAMETER_UPDATE_FAILURE_ERROR_CODE, PARAMETER_UPDATE_FAILURE_ERROR_MSGS);
        errorMessages.put(ACCESS_UNAUTHORIZED_ERROR_CODE, ACCESS_UNAUTHORIZED_ERROR_MSGS);
    }


    public String createSolutionMessage(final int errorCode, final Object... objectsForError) {
        final String solutionMessage = getSolutionForCode(errorCode);
        final MessageFormat messageFormat = new MessageFormat(solutionMessage);
        return messageFormat.format(objectsForError);
    }

    private String getErrorMessageForCode(final int errorCode) {
        return errorMessages.get(errorCode)[ERROR_MESSAGE_INDEX];
    }

    private String getSolutionForCode(final int errorCode) {
        return errorMessages.get(errorCode)[SOLUTION_MESSAGE_INDEX];
    }

    public String createErrorMessage(final int errorCode, final Object... objectsForError) {
        final String errorMessage = getErrorMessageForCode(errorCode);
        final MessageFormat messageFormat = new MessageFormat(errorMessage);
        return messageFormat.format(objectsForError);
    }

    public void printStackTraceIfEnable( final Throwable throwable) {
        final StringWriter stringWriter = new StringWriter();
        final PrintWriter printWriter = new PrintWriter(stringWriter);
        throwable.printStackTrace(printWriter);
        final String stackTraceResult = stringWriter.toString();
        LOGGER.error(" Exception StackTrace  : {}",stackTraceResult);
    }

}
