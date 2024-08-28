/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2013
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.services.cm.scriptengine.ejb.service.file;

import com.ericsson.oss.services.scriptengine.spi.dtos.file.FileDownloadResponseDto;
import com.ericsson.oss.services.scriptengine.spi.dtos.file.FileSystemLocatedFileDto;

import javax.ejb.Stateless;
import java.io.File;


@Stateless
public class ExportFileDownloadResponseDto {

    @SuppressWarnings("squid:S1068")
    private static final String MIME_TYPE = "text/xml";

    public FileDownloadResponseDto execute(final String fileId) {
        final File exportFile = new File(fileId);
        return new FileSystemLocatedFileDto(exportFile.getPath(), exportFile.getName(), MIME_TYPE);
    }
}
