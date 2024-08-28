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
package com.ericsson.oss.services.cm.admin.cli.response;

import static java.util.stream.Collectors.toList;
import static java.util.Optional.ofNullable;
import java.util.function.Function;
import java.util.List;
import java.util.Collection;
import java.util.Arrays;

import com.google.common.collect.ImmutableList;

import com.ericsson.oss.services.scriptengine.spi.dtos.RowCell;
import com.ericsson.oss.services.scriptengine.spi.dtos.RowDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.HeaderRowDto;

import static com.ericsson.oss.services.cm.error.ErrorHandlerImpl.SYNTAX_ERROR_CODE;
import static com.ericsson.oss.services.scriptengine.spi.dtos.ResponseStatus.COMMAND_EXECUTION_ERROR;
import static com.ericsson.oss.services.scriptengine.spi.dtos.ResponseStatus.COMMAND_SYNTAX_ERROR;
import com.ericsson.oss.services.scriptengine.spi.dtos.CommandResponseDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.ResponseDto;

public class CommandResponseDtoHelper {

    private static final ImmutableList<String> PARM_HEADERS = ImmutableList.of("Name", "Value");

    private final CommandResponseDto responseDto;

    public CommandResponseDtoHelper() {
        this.responseDto = new CommandResponseDto();
    }

    private CommandResponseDtoHelper(final String message) {
        this.responseDto = new CommandResponseDto();
        this.responseDto.setStatusMessage(message);
        this.responseDto.setStatusCode(CommandResponseDto.SUCCESS);
        this.responseDto.addSuccessLines();
    }

    private CommandResponseDtoHelper(final int errorCode, final String message, final String solution) {
        this.responseDto = new CommandResponseDto();
        this.responseDto.setCommand("admin");
        if (errorCode == SYNTAX_ERROR_CODE) {
            this.responseDto.setStatusCode(COMMAND_SYNTAX_ERROR);
        } else {
            this.responseDto.setStatusCode(COMMAND_EXECUTION_ERROR);
        }
        this.responseDto.setErrorCode(errorCode);
        this.responseDto.setStatusMessage(message);
        this.responseDto.setSolution(solution);
        this.responseDto.addErrorLines();
    }

    public static CommandResponseDtoHelper fromMessage(final String message) {
        return new CommandResponseDtoHelper(message);
    }

    public static CommandResponseDtoHelper fromErrorCode(final int errorCode, final String errorMessage, final String solution) {
        return new CommandResponseDtoHelper(errorCode, errorMessage, solution);
    }

    public CommandResponseDtoHelper withCommand(final String command) {
        this.responseDto.setCommand(command);
        return this;
    }

    public CommandResponseDtoHelper withStatusCode(final int statusCode) {
        this.responseDto.setStatusCode(statusCode);
        return this;
    }

    public CommandResponseDtoHelper withStatusMessage(final String statusMessage) {
        this.responseDto.setStatusMessage(statusMessage);
        return this;
    }

    public CommandResponseDtoHelper withResponseDto(final ResponseDto responseDto) {
        this.responseDto.setResponseDto(responseDto);
        return this;
    }

    public CommandResponseDtoHelper withErrorCode(final int errorCode) {
        this.responseDto.setErrorCode(errorCode);
        return this;
    }

    public CommandResponseDtoHelper withSolution(final String solution) {
        this.responseDto.setSolution(solution);
        return this;
    }

    public CommandResponseDtoHelper addLine(final String value) {
        this.responseDto.addLine(value);
        return this;
    }

    public CommandResponseDto getResponseDto() {
        return responseDto;
    }

    public CommandResponseDtoHelper appendParmDataTable(final Collection<String[]> parmList) {
        final List<RowDto> rows = parmList.stream().map(Arrays::asList).map(parmToRowDto).collect(toList());
        return appendResponseTable(getRowCells(PARM_HEADERS), rows);
    }

    private CommandResponseDtoHelper appendResponseTable(final List<RowCell> headers, final List<RowDto> rows) {
        this.responseDto.addEmptyLine();
        this.responseDto.getResponseDto().getElements().add(new HeaderRowDto(headers, ""));
        this.responseDto.getResponseDto().getElements().addAll(rows);
        appendItemsCountMessage(rows);
        return this;
    }

    private void appendItemsCountMessage(final Collection collection) {
        append(collection.size() + " parameter(s)");
    }

    private void append(final Object item) {
        if (item instanceof String) {
            this.responseDto.addLine((String) item);
        }
    }

    private Function<String, RowCell> stringToRowCell = item -> new RowCell(item, item.length());

    private List<RowCell> getRowCells(final List<String> strings) {
        return strings.stream()
            .map(stringToRowCell)
            .collect(toList());
    }

    private Function<List<String>, RowDto> parmToRowDto = parm -> new RowDto(
            getRowCells(parm)
            );
}
