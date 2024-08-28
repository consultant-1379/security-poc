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

package com.ericsson.itpf.security.pki.cmdhandler.mapper;

import java.util.*;

import javax.enterprise.context.ApplicationScoped;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException;
import com.ericsson.oss.services.scriptengine.spi.dtos.*;
import com.ericsson.oss.services.scriptengine.spi.dtos.file.FileDownloadRequestDto;
import com.ericsson.oss.services.scriptengine.spi.utils.TableBuilder;

/**
 * PkiToSEResponseMapper is responsible to perform proper translation of PkiCommandResponse objects and PkiServiceException exceptions into expected CM response components.
 *
 * @author xsumnan on 29/03/2015.
 */
@ApplicationScoped
public class PkiToSEResponseMapper {

    public static final String INVALID_NODES = "Invalid Nodes";
    @Inject
    private Logger logger;

    public static final int NODE_COLUMN = 0;
    public static final int ERROR_CODE_COLUMN = 1;
    public static final int ERROR_MESSAGE_COLUMN = 2;
    public static final int ERROR_SOLUTION_COLUMN = 3;
    public static final int INVALID_ITEMS = 1;
    public static final String ERROR = "Error ";
    public static final String SUGGESTED_SOLUTION = "Suggested Solution : ";
    public static final int SUCCESS_STATUS_CODE = 0;
    public static final String EMPTY_RESULT_LIST_MESSAGE = "Empty result list";
    public static final String INVALID_ITEMS_LIST_ERROR_MESSAGE = "One or more %ss are invalid";
    public static final String SUCCESS_DEFAULT_STATUS_MESSAGE = "Command Executed Successfully";
    public static final String INVALID_ITEMS_HEADER = "Problematic %ss";
    public static final String NODE_COLUMN_HEADER = "Node";
    public static final String ERROR_CODE_COLUMN_HEADER = "Error code";
    public static final String ERROR_MESSAGE_COLUMN_HEADER = "Error message";
    public static final String ERROR_SOLUTION_COLUMN_HEADER = "Suggested Solution";

    private String defaultErrorMessage = "";
    private String defaultSuggestedSolution = "";

    PkiToSEResponseMapper() {
        defaultErrorMessage = String.format("Error Code %d : %s", PkiWebCliException.ERROR_CODE_START_INT + PkiWebCliException.ErrorType.UNEXPECTED_ERROR.toInt(),
                PkiErrorCodes.UNEXPECTED_INTERNAL_ERROR);
        defaultSuggestedSolution = String.format("Suggested Solution : %s", PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR);
    }

    /**
     * Transform a PkiCommandResponse into a CommandResponseDto
     *
     * @param pkiCommandResponse
     *            PkiCommandResponse returned by a CommandHandler
     * @return Translated CommandResponseDto
     */
    public void convertToCommandResponseDto(final ResponseDto responseDto, final PkiCommandResponse pkiCommandResponse) {
        if (pkiCommandResponse.isMessageResponseType()) {
            final PkiMessageCommandResponse messageCommandResponse = (PkiMessageCommandResponse) pkiCommandResponse;
            if ((messageCommandResponse.getSuggestedSolution() == null) || messageCommandResponse.getSuggestedSolution().isEmpty()) {
                addMessages(responseDto, messageCommandResponse.getMessage());
            } else {
                addMessages(responseDto, messageCommandResponse.getMessage(), messageCommandResponse.getSuggestedSolution());
            }
        } else if (pkiCommandResponse.isDownloadRequestType()) {
            final PkiDownloadRequestToScriptEngine messageCommandResponse = (PkiDownloadRequestToScriptEngine) pkiCommandResponse;
            addDownLoadRequest(responseDto, messageCommandResponse.getFileIdentifier());
        } else if (pkiCommandResponse.isDownloadRequestMessageType()) {
            final PkiDownloadRequestMessageCommandResponse messageCommandResponse = (PkiDownloadRequestMessageCommandResponse) pkiCommandResponse;
            addDownLoadRequestMessage(responseDto, messageCommandResponse);
        } else if (pkiCommandResponse.isMessageMultipleValueType()) {
            final PkiMultipleMessageCommandResponse messageCommandResponse = (PkiMultipleMessageCommandResponse) pkiCommandResponse;
            addMessagesAsList(responseDto, messageCommandResponse.getMessage());
        } else if (pkiCommandResponse.isNameValueResponseType()) {
            final PkiNameValueCommandResponse nameValueCommandResponse = (PkiNameValueCommandResponse) pkiCommandResponse;
            if (nameValueCommandResponse.isEmpty()) {
                addMessages(responseDto, EMPTY_RESULT_LIST_MESSAGE);
            } else {
                final TableBuilder tableBuilder = new TableBuilder();

                int rowNumber = 0;
                final Iterator<PkiNameValueCommandResponse.Entry> iterator = nameValueCommandResponse.iterator();
                final PkiNameValueCommandResponse.Entry header = iterator.next();
                final String firstColumnTitle = header.getName();
                final String secondColumnTitle = header.getValue();

                final List<PkiNameValueCommandResponse.Entry> pairsWithHeaderRemoved = getPairsWithHeaderRemoved(iterator);
                final PkiNameValueCommandResponse.EntryComparator entryComparator = nameValueCommandResponse.new EntryComparator();
                Collections.sort(pairsWithHeaderRemoved, entryComparator);

                final Iterator<PkiNameValueCommandResponse.Entry> iter = pairsWithHeaderRemoved.iterator();
                tableBuilder.withHeader(0, firstColumnTitle);
                tableBuilder.withHeader(1, secondColumnTitle);

                while (iter.hasNext()) {
                    final PkiNameValueCommandResponse.Entry item = iter.next();
                    tableBuilder.withCell(rowNumber, 0, item.getName());
                    tableBuilder.withCell(rowNumber++, 1, item.getValue());
                }

                addTable(responseDto, tableBuilder);
                addMessages(responseDto, "", SUCCESS_DEFAULT_STATUS_MESSAGE);
            }
        } else if (pkiCommandResponse.isNameMultipleValueResponseType()) {
            logger.info("Command response type is :- PkiNameMultipleValueCommandResponse");
            final PkiNameMultipleValueCommandResponse nameMultipleValueCommandResponse = (PkiNameMultipleValueCommandResponse) pkiCommandResponse;
            if (nameMultipleValueCommandResponse.isEmpty()) {
                logger.debug("Empty response");
                addMessages(responseDto, EMPTY_RESULT_LIST_MESSAGE);

            } else {
                createTable(responseDto, nameMultipleValueCommandResponse);
                addMessages(responseDto, "", SUCCESS_DEFAULT_STATUS_MESSAGE);
            }
        } else if (pkiCommandResponse.isNameMultipleValueAndTableResponseType()) {
            logger.info("Command response type is :- PkiNameMultipleValueAndTableCommandResponse");
            final PkiNameMultipleValueAndTableCommandResponse nameMultipleValueAndTableCommandResponse = (PkiNameMultipleValueAndTableCommandResponse) pkiCommandResponse;
            if (nameMultipleValueAndTableCommandResponse.isEmpty()) {
                logger.debug("Empty response");
                addMessages(responseDto, EMPTY_RESULT_LIST_MESSAGE);
            } else {
                final Iterator iterator = nameMultipleValueAndTableCommandResponse.getMultipleValuesList().iterator();
                while (iterator.hasNext()) {
                    final PkiNameMultipleValueCommandResponse pkiNameValueResponse = (PkiNameMultipleValueCommandResponse) iterator.next();
                    createTable(responseDto, pkiNameValueResponse);
                    addMessages(responseDto, "");
                }
                addMessages(responseDto, SUCCESS_DEFAULT_STATUS_MESSAGE);
            }
        } else {
            logger.error("Unexpected response type found : {}", pkiCommandResponse);
            addMessages(responseDto, "Command executed successfully, but it is not possible to display the result.");
        }
    }

    /**
     * @param responseDto
     * @param nameMultipleValueCommandResponse
     */
    private void createTable(final ResponseDto responseDto, final PkiNameMultipleValueCommandResponse nameMultipleValueCommandResponse) {
        final int valueSize = nameMultipleValueCommandResponse.getValueSize();
        logger.debug("valueSize {}", valueSize);

        final TableBuilder tableBuilder = new TableBuilder();

        final Iterator<PkiNameMultipleValueCommandResponse.Entry> iterator = nameMultipleValueCommandResponse.iterator();
        final PkiNameMultipleValueCommandResponse.Entry header = iterator.next();

        int colNumber = 0;
        tableBuilder.withHeader(colNumber, header.getName());
        final String[] headerValue = header.getValues();
        for (final String headerText : headerValue) {
            tableBuilder.withHeader(++colNumber, headerValue[colNumber - 1]);
        }

        int rowNumber = 0;
        while (iterator.hasNext()) {
            final PkiNameMultipleValueCommandResponse.Entry item = iterator.next();

            tableBuilder.withCell(rowNumber, 0, item.getName());

            final String[] itemValue = item.getValues();
            for (int i = 0; i < itemValue.length; i++) {
                tableBuilder.withCell(rowNumber, i + 1, itemValue[i]);
            }
            rowNumber++;
        }
        logger.debug("rowNumber {}", rowNumber);
        if (!nameMultipleValueCommandResponse.getAdditionalInformation().isEmpty()) {
            addMessages(responseDto, nameMultipleValueCommandResponse.getAdditionalInformation());
        }
        addTable(responseDto, tableBuilder);
    }

    /**
     * Constructs a CommandResponseDto containing a ResponseDto with an array of LineDtos. Each LineDto contains one message
     *
     * @param responseDto
     *            The responseDto into which the messages are added.
     * @param messages
     *            Each message as a single String
     * @return CommandResponseDto
     */
    public void constructMessageResponse(final ResponseDto responseDto, final String... messages) {
        addMessages(responseDto, messages);
    }

    /**
     * builds FileDownloadRequestDto and adds it to the ResponseDto passed in.
     *
     * @param responseDto
     *            The responseDto into which the table is added.
     * @param fileid
     *            The key with which file download will be triggered from ScriptEngine
     */
    private void addDownLoadRequest(final ResponseDto responseDto, final String fileid) {
        final List<AbstractDto> responseLines = responseDto.getElements();
        responseLines.add(new FileDownloadRequestDto(PkiCommand.APP_ID, fileid));
        responseDto.getElements().addAll(responseLines);
    }

    private void addDownLoadRequestMessage(final ResponseDto responseDto, final PkiDownloadRequestMessageCommandResponse downloadMessageResponse) {
        responseDto.getElements().add(new FileDownloadRequestDto(PkiCommand.APP_ID, downloadMessageResponse.getFileIdentifier()));
        responseDto.getElements().add(createLineDto(downloadMessageResponse.getMessage()));
    }

    /**
     * Receives a Table (in TableBuilder format), builds the table and adds it to the ResponseDto passed in.
     *
     * @param responseDto
     *            The responseDto into which the table is added.
     * @param tableBuilder
     *            The TableBuilder containing the RowDtos and HeaderRowDto
     */
    public void addTable(final ResponseDto responseDto, final TableBuilder tableBuilder) {
        final List<RowDto> rows = tableBuilder.build();
        responseDto.getElements().addAll(rows);
    }

    /**
     * Creates a CommandResponseDto with one error message
     *
     * @param responseDto
     *            The responseDto into which the error message will be added
     * @param statusMessage
     *            The error message to be added
     * @return CommandResponseDto
     */
    public void createErrorCommandResponse(final ResponseDto responseDto, final String statusMessage) {
        constructMessageResponse(responseDto, statusMessage);
    }

    /**
     * Add one or more messages to a ResponseDto to be displayed by ScriptEngine to the CLI UI.
     *
     * @param responseDto
     *            The responseDto into which the messages will be added
     * @param messages
     *            The messages to be added
     */
    public void addMessages(final ResponseDto responseDto, final String... messages) {
        for (final String message : messages) {
            responseDto.getElements().add(createLineDto(message));
        }
    }

    /**
     * Add one or more messages to a ResponseDto to be displayed by ScriptEngine to the CLI UI.
     * 
     * @param responseDto
     *            The responseDto into which the messages will be added
     * @param messages
     *            The messages to be added
     */
    public void addMessagesAsList(final ResponseDto responseDto, final List<String> messages) {
        for (final String message : messages) {
            responseDto.getElements().add(createLineDto(message));
        }
    }

    /**
     * Add the Standard Error Message to the ResponseDto passed in.
     *
     * @param responseDto
     *            The responseDto into which the standard Error message will be added
     */
    public void createErrorCommandResponse(final ResponseDto responseDto) {
        addMessages(responseDto, defaultErrorMessage, defaultSuggestedSolution);
    }

    /**
     * Add the Summary ResponseDto Values from PkiMessageCommandResponse to CommandResponseDto
     *
     * @param commandResponse
     *            PkiMessageCommandResponse having SummaryResponseDto Values
     * @param commandResponseDto
     *            CommandResponseDto in which the SummaryResponseDto values will be added
     */
    public void setSummaryForMessageCommandResponse(final PkiCommandResponse commandResponse, final CommandResponseDto commandResponseDto) {
        if (commandResponse.isMessageResponseType()) {
            final PkiMessageCommandResponse messageCommandResponse = (PkiMessageCommandResponse) commandResponse;

            if ((messageCommandResponse.getErrorCode() != 0)) {
                commandResponseDto.setErrorCode(messageCommandResponse.getErrorCode());
                commandResponseDto.setErrorMessage(messageCommandResponse.getErrorMessage());
                commandResponseDto.setSolution(messageCommandResponse.getSuggestedSolution());
                commandResponseDto.setStatusMessage(messageCommandResponse.getErrorMessage());
            }
        }
    }

    private LineDto createLineDto(final String lineEntry) {
       return new LineDto(lineEntry);
    }

    private List<PkiNameValueCommandResponse.Entry> getPairsWithHeaderRemoved(final Iterator<PkiNameValueCommandResponse.Entry> iterator) {

        final List<PkiNameValueCommandResponse.Entry> pairsWithHeaderRemoved = new LinkedList<>();

        while (iterator.hasNext()) {
            final PkiNameValueCommandResponse.Entry item = iterator.next();
            pairsWithHeaderRemoved.add(item);
        }

        return pairsWithHeaderRemoved;
    }
}
