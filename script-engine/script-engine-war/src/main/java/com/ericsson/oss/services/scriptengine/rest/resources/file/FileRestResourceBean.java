
package com.ericsson.oss.services.scriptengine.rest.resources.file;

import java.io.IOException;
import java.io.OutputStream;

import javax.annotation.PostConstruct;
import javax.inject.Inject;
import javax.ws.rs.core.Response;
import javax.ws.rs.core.Response.Status;
import javax.ws.rs.core.StreamingOutput;

import org.apache.http.HttpStatus;

import com.ericsson.oss.itpf.sdk.core.classic.ServiceFinderBean;
import com.ericsson.oss.services.cm.scriptengine.ejb.service.file.FileHandlerBean;
import com.ericsson.oss.services.scriptengine.spi.FileDownloadHandler;
import com.ericsson.oss.services.scriptengine.spi.dtos.file.FileDownloadResponseDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.file.FileSystemLocatedFileDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.file.InMemoryFileDto;
import com.ericsson.oss.services.cm.scriptengine.ejb.service.file.ExportFileDownloadResponseDto;
import org.slf4j.Logger;

/**
 * {@link FileRestResource} implementation.
 *
 * @since 1.6.2
 */
public class FileRestResourceBean implements FileRestResource {

    private ServiceFinderBean serviceFinder;

    @Inject
    private FileHandlerBean fileHandlerBean;

    @Inject
    private ExportFileDownloadResponseDto exportFileDownloadResponseDto;

    @Inject
    private Logger logger;

    private final FilePathAccessChecker filePathAccessChecker = new FilePathAccessChecker();

    @PostConstruct
    public void init() {
        serviceFinder = new ServiceFinderBean();
    }

    @Override
    public Response downloadFile(final String applicationId, final String fileId) {
        Response response = null;
        try {
            if (filePathAccessChecker.isDownloadPermitted(applicationId, fileId)) {
                final FileDownloadHandler fileDownloadHandler = serviceFinder.find(FileDownloadHandler.class, applicationId);
                final FileDownloadResponseDto fileResponseDto = fileDownloadHandler.execute(fileId);
                if (fileResponseDto instanceof InMemoryFileDto) {
                    response = downloadFromMemory((InMemoryFileDto) fileResponseDto);
                } else if (fileResponseDto instanceof FileSystemLocatedFileDto) {
                    response = downloadFromFilesystem((FileSystemLocatedFileDto) fileResponseDto);
                }
            } else {
                return Response.status(HttpStatus.SC_FORBIDDEN).build();
            }
        } catch (final Exception e) {
            logger.error("downloadFile applicationId = {} fileId = {}  Exception message = {}",applicationId, fileId, e.getMessage());
            response = Response.serverError().build();
        }
        return response;
    }

    /*
     * P R I V A T E - M E T H O D S
     */
    private Response downloadFromMemory(final InMemoryFileDto fileDto) {
        return buildDownloadFileResponse(fileDto.getFileContents(), fileDto.getFileName(), fileDto.getMimeType());
    }

    private Response downloadFromFilesystem(final FileSystemLocatedFileDto fileDto) {
        Response response = null;
        final String filePath = fileDto.getFilePath();
        if (fileHandlerBean.exists(filePath)) {
            final StreamingOutput outputStream = new ResourceStreamingOutput(filePath);
            response = buildDownloadFileResponse(outputStream, fileDto.getFileName(), fileDto.getMimeType());
        } else {
            response = Response.status(Status.NOT_FOUND).build();
        }
        return response;
    }

    private Response buildDownloadFileResponse(final Object entity, final String fileName, final String mimeType) {
        return Response.ok(entity).type(mimeType)
                .header("Content-Disposition", "attachment; filename=" + fileName).build();
    }

    /**
     * Response entity to stream <code>Resource</code> output.
     */
    class ResourceStreamingOutput implements StreamingOutput {

        private final String filePath;

        public ResourceStreamingOutput(final String filePath) {
            this.filePath = filePath;
        }

        @Override
        public void write(final OutputStream output) throws IOException {
            fileHandlerBean.writeToStream(filePath, output);
        }
    }

}
