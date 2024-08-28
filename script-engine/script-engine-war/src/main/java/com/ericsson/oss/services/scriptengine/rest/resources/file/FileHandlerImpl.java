
package com.ericsson.oss.services.scriptengine.rest.resources.file;

import static javax.ws.rs.core.Response.serverError;

import static com.ericsson.oss.services.cm.scriptengine.ejb.service.file.ScriptEngineCacheToFileConstants.OUTPUT_TO_FILE_FINAL_FILE_NAME;

import java.io.File;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.Collection;
import java.util.Collections;
import java.util.List;

import javax.enterprise.inject.Default;
import javax.inject.Inject;
import javax.ws.rs.core.MediaType;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.StreamingOutput;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.services.cm.scriptengine.ejb.service.file.FileHandlerBean;
import com.google.common.collect.Lists;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

@Default
public class FileHandlerImpl implements FileHandler {

    @Inject
    private FileHandlerBean fileHandlerBean;

    @Inject
    private SystemRecorder systemRecorder;

    private static final Logger logger = LoggerFactory.getLogger(FileHandlerImpl.class);

    public static final String UNIX_FILE_PATH = "/ericsson/config_mgt/script_engine";
    private static final String FILENAME_IDENTIFIER = "_";

    @Override
    public String write(final String fileName, final InputStream inputStream) throws IOException {
        try {
            long startTime = System.currentTimeMillis();
            final String filePathUri = generateAbsoluteFileUri(fileName.toString());
            int size;
            int fullFileSize = 0;
            final byte[] buffer = new byte[10485760];
            while ((size = inputStream.read(buffer, 0, buffer.length)) > 0) {
                fullFileSize += size;
                if (size == buffer.length) {
                    fileHandlerBean.writeFile(filePathUri, buffer);
                } else {
                    final byte[] buffer1 = new byte[size];
                    System.arraycopy(buffer, 0, buffer1, 0, size);
                    fileHandlerBean.writeFile(filePathUri, buffer1);
                }

            }
            long deltaTime = System.currentTimeMillis() - startTime;

            logger.info(" FileHandlerImpl write file: {}  with size={}M  in ms = {} ",filePathUri,(fullFileSize/1024),deltaTime);
            return filePathUri;
        } finally {
            inputStream.close();
        }
    }

    @Override
    public boolean exists(final String filePath) {
        return fileHandlerBean.exists(filePath);
    }

    @Override
    public String getOutputToFileDownloadDirectoryPath() {
        return fileHandlerBean.getOutputToFileDownloadDirectoryPath();
    }

    @Override
    public Response createResponseFromFile(final String requestId, final String userFilename) {
        final String folderPath = getFolderPath(requestId);
        final Collection<String> fileNames = fileHandlerBean.getFileNamesInDirectory(folderPath);
        if (fileNames.size() == 1) {
            final String fileName = fileNames.iterator().next();
            final StreamingOutput streamingOutput = new SingleResourceStreamingOutput(folderPath + fileName);
            return buildDownloadFileResponse(streamingOutput, userFilename, MediaType.TEXT_PLAIN);
        } else if (fileNames.size() > 1) {
            final StreamingOutput streamingOutput = new MultipleResourceStreamingOutput(folderPath, orderFileNames(fileNames));
            return buildDownloadFileResponse(streamingOutput, userFilename, MediaType.TEXT_PLAIN);
        } else {
            recordHttp500InternalServerError("No files found for requestId: " + requestId, "createResponseFromFile");
            return serverError().build();
        }
    }

    /*
     * P R I V A T E - M E T H O D S
     */

    private String generateAbsoluteFileUri(final String fileName) {
        return (UNIX_FILE_PATH + File.separator + System.currentTimeMillis() + FILENAME_IDENTIFIER + fileName);
    }

    private String getFolderPath(final String requestId) {
        return fileHandlerBean.getOutputToFileDownloadDirectoryPath() + requestId + "/";
    }

    private List<String> orderFileNames(final Collection<String> fileNames) {
        boolean lastFileFound = false;
        if (fileNames.contains(OUTPUT_TO_FILE_FINAL_FILE_NAME)) {
            lastFileFound = true;
            fileNames.remove(OUTPUT_TO_FILE_FINAL_FILE_NAME);
        }
        final List<String> sortedFileNames = Lists.newArrayList(fileNames.iterator());
        Collections.sort(sortedFileNames);
        if (lastFileFound) {
            sortedFileNames.add(OUTPUT_TO_FILE_FINAL_FILE_NAME);
        }
        return sortedFileNames;
    }

    private Response buildDownloadFileResponse(final Object entity, final String fileName, final String mimeType) {
        return Response.ok(entity).type(mimeType)
                .header("Content-Disposition", "attachment; filename=" + fileName).build();
    }

    public void recordHttp500InternalServerError(final String source, final String callingMethod) {
        systemRecorder.recordError("500 Internal Server Error", ErrorSeverity.ERROR, "CM CLI REST Client", source,
                callingMethod);
    }

    /*
     * P R I V A T E - C L A S S E S
     */

    /**
     * Response entity to stream <code>Resource</code> output.
     */
    class SingleResourceStreamingOutput implements StreamingOutput {

        private final String filePath;

        public SingleResourceStreamingOutput(final String filePath) {
            this.filePath = filePath;
        }

        @Override
        public void write(final OutputStream outputStream) throws IOException {
            fileHandlerBean.writeToStream(filePath, outputStream);
        }
    }

    /**
     * Response entity to stream <code>Resource</code> output.
     */
    class MultipleResourceStreamingOutput implements StreamingOutput {

        private final String folderPath;
        private final List<String> fileNames;

        public MultipleResourceStreamingOutput(final String folderPath, final List<String> fileNames) {
            this.folderPath = folderPath;
            this.fileNames = fileNames;
        }

        @Override
        public void write(final OutputStream outputStream) throws IOException {
            fileHandlerBean.writeMultipleFilesToStream(folderPath, fileNames, outputStream);
        }
    }
}
