
package com.ericsson.oss.services.scriptengine.rest.resources.file;

import java.io.IOException;
import java.io.InputStream;

import javax.ws.rs.core.Response;

public interface FileHandler {

    String write(String fileName, InputStream inputStream) throws IOException;

    boolean exists(final String filePath);

    Response createResponseFromFile(String requestId, String userFilename);

    String getOutputToFileDownloadDirectoryPath();

}
