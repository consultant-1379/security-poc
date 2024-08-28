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

package com.ericsson.itpf.security.pki.cmdhandler.util;

import java.io.File;
import java.io.IOException;
import java.net.URLDecoder;
import java.nio.charset.Charset;
import java.nio.file.*;
import java.util.*;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.*;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.CommandSyntaxException;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiWebCliException.ErrorType;
import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;

/**
 * Utility to get content of input file through web cli And other utilities.
 *
 * @author xsumnan
 *
 */
public class CliUtil {
    public static final String FOUND_NO_DATA = "Could not find file data in";

    @Inject
    Logger logger;

    @Inject
    ExportedItemsHolder exportedItemsHolder;

    /**
     * Method to fetch the content of input txt or xml file(readable file)
     *
     * @param properties
     * @return String
     * @throws CommandSyntaxException
     *             in case input file is not proper
     */
    public String getFileContentFromCommandProperties(final Map<String, Object> properties) throws CommandSyntaxException {
        String content = null;

        final String filePath = (String) properties.get("filePath");

        if (filePath != null && !filePath.isEmpty()) {
            final String osAppropriatePath = Constants.FILE_SEPARATOR.equalsIgnoreCase("/") ? filePath : filePath.substring(1);
            try {
                final Path path = Paths.get(URLDecoder.decode(osAppropriatePath, "UTF-8"));
                final Charset charset = Charset.forName("UTF-8");
                final byte[] data = Files.readAllBytes(path);
                content = new String(data, charset);
            } catch (final IOException e) {
                logger.error(Arrays.toString(e.getStackTrace()));
                logger.debug("{} [{}]", FOUND_NO_DATA, filePath);
                logger.error(e.getMessage());
                throw new CommandSyntaxException();
            }
        } else {
            logger.debug("{} [{}]", FOUND_NO_DATA, filePath);
            throw new CommandSyntaxException();
        }

        if (content.isEmpty()) {
            logger.debug("File [{}] is empty", filePath);
            throw new CommandSyntaxException();
        }
        return content;
    }

    /**
     * This Method is used to fetch binary data from input file such as csr file
     *
     * @param Map
     *            <String, Object> properties
     * @return byte[]
     * @throws CommandSyntaxException
     *             in case input file is not proper
     */
    public byte[] getFileBytesFromCommandProperties(final Map<String, Object> properties) {
        final String filePath = (String) properties.get("filePath");
        byte[] data;
        if (filePath != null && !filePath.isEmpty()) {
            final String osAppropriatePath = Constants.FILE_SEPARATOR.equalsIgnoreCase("/") ? filePath : filePath.substring(1);
            try {
                final Path path = Paths.get(URLDecoder.decode(osAppropriatePath, "UTF-8"));
                data = Files.readAllBytes(path);
            } catch (final IOException e) {
                logger.error("{} [{}] " + Constants.NEXT_LINE + " {}", FOUND_NO_DATA, filePath, e.getMessage());
                throw new CommandSyntaxException();
            }
        } else {
            logger.error("{} [{}]", FOUND_NO_DATA, filePath);
            throw new CommandSyntaxException();
        }

        return data;
    }

    /**
     * Method to implement filter based on criteria
     *
     * @param list
     * @param criteria
     * @return List
     */
    public static <T> List<T> filter(final List<T> list, final CliPredicate<T> criteria) {
        final List<T> result = new ArrayList<>();

        for (final T element : list) {
            if (criteria.apply(element)) {
                result.add(element);
            }
        }

        return result;
    }

    /**
     * Method for checking if given list is null or empty
     *
     * @param givenList
     * @return true or false
     */
    public static boolean isNullOrEmpty(final List<?> givenList) {
        if (givenList == null || givenList.isEmpty()) {
            return true;
        }

        return false;
    }

    /**
     * Method for checking if given String is null or empty
     *
     * @param str
     * @return true or false
     */
    public static boolean isNullOrEmpty(final String str) {
        if (str == null || str.isEmpty()) {
            return true;
        }

        return false;
    }

    /**
     * Add multiple String into single String to be sent as response. This can be used later when required.
     *
     * @param parts
     * @return String
     */
    // TODO Ciphers Can be removed later if not required
    @SuppressWarnings("unused")
    private String join(final Collection<String> parts) {
        final StringBuilder buffer = new StringBuilder();
        if (parts != null) {
            for (final String part : parts) {
                if (buffer.length() > 0) {
                    buffer.append(", ");
                }
                buffer.append(part);
            }
        }
        return buffer.toString();
    }

    /**
     * Method that generate key based on the timestamp to keep the file in memory
     *
     * @return String
     */
    public static synchronized String generateKey() {
        return "_" + System.currentTimeMillis();
    }

    /**
     * Method for preparing error message
     *
     * @param errorCode
     * @param errorMessage
     * @return String
     */
    public static String buildMessage(final int errorCode, final String errorMessage) {
        return "Error: " + (PkiWebCliException.ERROR_CODE_START_INT + errorCode) + Constants.SPACE_STRING + errorMessage;
    }

    /**
     * Method for preparing error message
     *
     * @param errorCode
     *            Error code to given to user
     * @param errorString
     *            Error string that would be given to user
     * @param errorMessage
     *            EXception traces given to user
     * @return String
     */
    public static String buildMessage(final int errorCode, final String errorString, final String errorMessage) {
        return "Error: " + (PkiWebCliException.ERROR_CODE_START_INT + errorCode) + Constants.SPACE_STRING + errorString + Constants.SPACE_STRING + errorMessage;
    }

    /**
     * common method for printing message to user on console
     *
     * @param errorCode
     *            Error code to given to user
     * @param errorMessage
     *            EXception traces given to user
     * @param logErrorMessage
     *            error message that would go in logger.
     * @param cause
     *            Exception that is raised
     * @return message
     */

    public PkiCommandResponse prepareErrorMessage(final int errorCode, final String errorString, final String errorMessage) {
        logger.error("Error occured due to {} " ,errorMessage);
        return new PkiMessageCommandResponse(CliUtil.buildMessage(errorCode, errorString, errorMessage), PkiWebCliException.ERROR_CODE_START_INT + errorCode,
                errorString + Constants.COMMA + errorMessage, Constants.EMPTY_STRING);
    }

    /**
     * Method for Creating Temporary File
     *
     * @param fileName
     * @param fileExtension
     * @return
     */
    public static String getTempFile(final String fileName, final String fileExtension) {
        return Constants.TMP_DIR + Constants.FILE_SEPARATOR + fileName + fileExtension;
    }

    /**
     * <p>
     * Method for splitting a string with delimiter like ,
     * </p>
     *
     * @param input
     * @param delimiter
     * @return List<String>
     */
    public List<String> splitBySeprator(final String input, final String seprator) {

        List<String> result = null;
        if (ValidationUtils.isNullOrEmpty(input)) {
            return result;
        }
        final String[] tokens = input.split(seprator);
        result = Arrays.asList(tokens);
        return result;
    }

    /**
     * Method for building command response to download a file
     *
     * @param fileName
     * @param contentType
     * @param content
     *
     * @return commandResponse
     */

    public PkiCommandResponse buildPkiCommandResponse(final String fileName, final String contentType, final byte[] content) {
        final String fileIdentifier = CliUtil.generateKey();
        final DownloadFileHolder downloadFileHolder = generateDownloadFileHolder(fileName, contentType, content);

        exportedItemsHolder.save(fileIdentifier, downloadFileHolder);

        final PkiDownloadRequestToScriptEngine commandResponse = new PkiDownloadRequestToScriptEngine();
        commandResponse.setFileIdentifier(fileIdentifier);
        logger.debug("Downloadable content stored in memory with fileidentifier {}", fileIdentifier);

        return commandResponse;
    }

    /**
     * Method for building command response to download a file
     *
     * @param fileName
     * @param contentType
     * @param content
     * @param message
     *
     * @return commandResponse
     */

    public PkiCommandResponse buildPkiCommandResponse(final String fileName, final String contentType, final byte[] content, final String message) {
        final String fileIdentifier = CliUtil.generateKey();
        final DownloadFileHolder downloadFileHolder = generateDownloadFileHolder(fileName, contentType, content);

        exportedItemsHolder.save(fileIdentifier, downloadFileHolder);

        final PkiDownloadRequestMessageCommandResponse commandResponse = new PkiDownloadRequestMessageCommandResponse();
        commandResponse.setFileIdentifier(fileIdentifier);
        commandResponse.setMessage(message);
        logger.debug("Downloadable content stored in memory with fileidentifier {}", fileIdentifier);

        return commandResponse;
    }

    private DownloadFileHolder generateDownloadFileHolder(final String fileName, final String contentType, final byte[] content) {

        final DownloadFileHolder downloadFileHolder = new DownloadFileHolder();
        downloadFileHolder.setFileName(fileName);
        downloadFileHolder.setContentType(contentType);
        downloadFileHolder.setContentToBeDownloaded(content);

        return downloadFileHolder;
    }

    /**
     * <p>
     * Method for splitting a string with delimiter like ,
     * </p>
     *
     * @param input
     * @param delimiter
     * @return List<String>
     */
    public List<String> splitBySeparator(final String input, final String separator) {

        List<String> result = null;
        if (ValidationUtils.isNullOrEmpty(input)) {
            return result;
        }
        final String[] tokens = input.split(separator);
        result = Arrays.asList(tokens);
        return result;
    }

    /**
     * <p>
     * Method for removing the Square brackets as a first and last character,
     * </p>
     *
     * @param input
     * @return String
     */
    public String removeFirstAndLastChar(final String input) {
        if (input.startsWith("[") && input.endsWith("]")) {
            return input.replaceAll(Constants.REMOVE_UNWANTED_SQUARE_BRACKETS_REGEX, "");
        }
        return input;

    }

    /**
     * <p>
     * Method for removing the unwanted commas from the input StringBuilder.
     * </p>
     *
     * @param input
     * @return String
     */
    public String removeUnwantedCommaFromString(final StringBuilder input) {
        final String respone = input.toString().replace(Constants.REMOVE_UNWANTED_SQUARE_BRACKETS_REGEX, "").replaceAll(Constants.REMOVE_UNWANTED_COMMA_REGEX, "");
        if (respone.contains(",")) {
            return respone.replace(respone.substring(respone.lastIndexOf(',')), " and " + respone.substring(respone.lastIndexOf(',') + 1));
        } else {
            return respone;
        }
    }

    /**
     * <p>
     * Method to get ErrorCode.
     * </p>
     *
     * @param errorType
     * @return Integer
     */
    public Integer getErrorCode(final ErrorType errorType) {

        return (PkiWebCliException.ERROR_CODE_START_INT + errorType.toInt());
    }

    /**
     * Method to fetch the input file name
     *
     * @param properties
     *            command properties
     * @return String
     *            name of the input file
     * @throws CommandSyntaxException
     *             in case input file is not proper
     */
    public String getFileNameFromCommandProperties(final Map<String, Object> properties) throws CommandSyntaxException {

        final String filePath = (String) properties.get("filePath");
        if (filePath != null && !filePath.isEmpty()) {
            final File file = new File(filePath);
            final String tempfileName = file.getName();
            if (tempfileName != null) {
                final String[] tempFileNameArr = tempfileName.split("\\."); // to remove extension
                final String[] fileNameArr = tempFileNameArr[0].split("_", 2); // to remove timestamp prepended
                if (fileNameArr.length > 1) {
                    return fileNameArr[1];
                }
            }
            return tempfileName;
        } else {
            logger.debug("Unable to get file name from path {}", filePath);
            throw new CommandSyntaxException();
        }
    }
}
