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
package com.ericsson.oss.services.cm.scriptengine.ejb.service.stubs;

import java.io.BufferedWriter;
import java.io.File;
import java.io.FileWriter;
import java.io.IOException;

import javax.ejb.Stateless;
import javax.inject.Inject;

import com.ericsson.oss.itpf.sdk.context.ContextService;
import com.ericsson.oss.itpf.sdk.core.annotation.EServiceQualifier;
import com.ericsson.oss.services.scriptengine.spi.FileDownloadHandler;
import com.ericsson.oss.services.scriptengine.spi.dtos.file.FileDownloadResponseDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.file.FileSystemLocatedFileDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.file.InMemoryFileDto;

/**
 * {@link FileDownloadHandler} implementation for arquillian tests.
 *
 */
@Stateless
@EServiceQualifier("FileDownloadHandlerImpl")
public class FileDownloadHandlerImpl implements FileDownloadHandler {

    @Inject
    private ContextService contextService;

    public static final String FILE_NAME = "tmpFile";
    public static final String FILE_EXT = ".txt";
    public static final String FILE_CONTENTS = "some file content";
    public static final String AUTHENTICATED_USER_ID = "authenticatedUserId";

    @Override
    @SuppressWarnings("PMD.AvoidThrowingRawExceptionTypes")
    public FileDownloadResponseDto execute(final String fileId) {
        File tempFile = null;
        try {
            tempFile = createTempFile();
        } catch (final IOException e) {
            return null;
        }
        final String userId = contextService.getContextValue("X-Tor-UserID");
        if (!AUTHENTICATED_USER_ID.equals(userId)) {
            throw new RuntimeException("Incorrect User ID, expected '" + AUTHENTICATED_USER_ID + "' but found '" + userId + "'");
        }
        if (fileId.contains("inMemory")) {
            return new InMemoryFileDto(FILE_CONTENTS.getBytes(), tempFile.getName(), "text/plain");
        } else {
            return new FileSystemLocatedFileDto(tempFile.getPath(), tempFile.getName(), "text/plain");
        }
    }

    public File createTempFile() throws IOException {
        File tempFile = null;
        tempFile = File.createTempFile(FILE_NAME, FILE_EXT);
        final BufferedWriter bufferedWriter = new BufferedWriter(new FileWriter(tempFile));
        bufferedWriter.write(FILE_CONTENTS);
        bufferedWriter.close();
        tempFile.deleteOnExit();
        return tempFile;
    }

    public void setContextServiceStub(final ContextService stub) {
        // Required for testing purposes
        contextService = stub;
    }

}
