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

import java.io.*;
import java.util.Collection;
import java.util.Collections;
import java.util.Enumeration;
import java.util.Iterator;
import java.util.List;
import java.util.Vector;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.sdk.resources.Resource;
import com.ericsson.oss.itpf.sdk.resources.ResourcesException;
import com.google.common.collect.Lists;

import static com.ericsson.oss.services.cm.scriptengine.ejb.service.file.ScriptEngineCacheToFileConstants.DEFAULT_OUTPUT_TO_FILE_DOWNLOAD_FOLDER_PATH;
import static com.ericsson.oss.services.cm.scriptengine.ejb.service.file.ScriptEngineCacheToFileConstants.OUTPUT_TO_FILE_DOWNLOAD_FOLDER_PATH_PROPERTY;
@Stateless
public class FileHandlerBean {

    private static final int BUFFER_SIZE = 1024;
    @SuppressWarnings("squid:S1075")
    private static final String RESTEASY_TMP_PATH = "/tmp";

    private final static Logger logger = LoggerFactory.getLogger(FileHandlerBean.class);

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    private ResourcesBean resources;

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public void writeFile(final String absoluteFileUri, final byte[] fileData) throws ResourcesException {
        final Resource resource = resources.getFileSystemResource(absoluteFileUri);
        final boolean append = true;
        resource.write(fileData, append);
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public void writeToStream(final String filePath, final OutputStream outputStream) throws IOException {
        final Resource resource = resources.getFileSystemResource(filePath);
        if (resource.exists()) {
            try (InputStream inputStream = resource.getInputStream()) {
                writeFromInputStreamToOutputStream(inputStream, outputStream);
            }
        } else {
            systemRecorder.recordError("SCRIPT_ENGINE.FILE_DELETED", ErrorSeverity.ERROR, null, "script-engine",
                    "The following file: " + filePath
                            + " was not written to stream from the file system as the file does not exist in the specified location.");
        }
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public void writeMultipleFilesToStream(final String directoryPath, final List<String> orderedFileNames, final OutputStream outputStream)
            throws IOException {
        final Resource directoryResource = resources.getFileSystemResource(directoryPath);
        if (directoryResource.exists()) {
            final Collection<Resource> fileResources = directoryResource.listFiles();
            final Enumeration<? extends InputStream> orderedFileInputStreams = orderFileInputStreams(orderedFileNames, fileResources);

            if (fileResources.size() > 0) {
                try (SequenceInputStream sequenceInputStream = new SequenceInputStream(orderedFileInputStreams)) {
                    writeFromInputStreamToOutputStream(sequenceInputStream, outputStream);
                }
            } else {
                systemRecorder.recordError("SCRIPT_ENGINE.DIRECTORY_EMPTY", ErrorSeverity.ERROR, null, "script-engine",
                        "Directory: " + directoryPath
                                + " does not contain any files to be written to stream.");
            }
        } else {
            systemRecorder.recordError("SCRIPT_ENGINE.DIRECTORY_DELETED", ErrorSeverity.ERROR, null, "script-engine",
                    "Files from directory: " + directoryPath
                            + " were not written to stream from the file system as the directory does not exist in the specified location.");
        }
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public void deleteDirectory(final String directoryPath) {
        final Resource resource = resources.getFileSystemResource(directoryPath);
        if (resource.isDirectoryExists()) {
            resource.deleteDirectory();
            logger.debug("Directory {} deleted", directoryPath);
        } else {
            systemRecorder.recordError("SCRIPT_ENGINE.DIRECTORY_NOT_DELETED", ErrorSeverity.ERROR, null, "script-engine", "The following file: "
                    + directoryPath + " was not deleted from the file system as the file does not exist in the specified location.");
        }
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public Collection<String> getFileNamesInDirectory(final String directoryPath) {
        final Resource directoryResource = resources.getFileSystemResource(directoryPath);
        final Collection<String> fileNames = Lists.newArrayList();
        if (directoryResource.isDirectoryExists()) {
            final Collection<Resource> fileResources = directoryResource.listFiles();
            for (final Resource fileResource : fileResources) {
                fileNames.add(fileResource.getName());
            }
            return fileNames;
        }
        return Collections.emptyList();
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public void purgeOlderFiles(final String directoryPath, final long ageInMilliseconds) {
        final long currentTimeInMilliseconds = System.currentTimeMillis();
        final Resource resource = resources.getFileSystemResource(directoryPath);
        if (resource.isDirectoryExists()) {
            final Collection<Resource> fileResources = resource.listFiles();
            for (final Resource fileResource : fileResources) {
                resource.setURI(directoryPath.concat(File.separator).concat(fileResource.getName()));
                final boolean fileCanBeDeleted = resource.getLastModificationTimestamp() < currentTimeInMilliseconds - ageInMilliseconds;
                if (fileCanBeDeleted) {
                    resource.delete();
                    logger.debug("purgeOlderFiles - deleted filename: {} form path:{}", resource.getName(),directoryPath);
                }
            }
        }
        logger.debug("purgeOlderFiles - completed");
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public void purgeOlderRestEasyFiles(final long ageInMilliseconds) {
        final long currentTimeInMilliseconds = System.currentTimeMillis();
        final Resource resource = resources.getFileSystemResource(RESTEASY_TMP_PATH);
        if (resource.isDirectoryExists()) {
            final Collection<Resource> fileResources = resource.listFiles();
            for (final Resource fileResource : fileResources) {
                if (isTemporaryRestEasyFile(fileResource.getName(), fileResource.supportsWriteOperations())) {
                    resource.setURI(RESTEASY_TMP_PATH.concat(File.separator).concat(fileResource.getName()));
                    final boolean fileCanBeDeleted = resource.getLastModificationTimestamp() < currentTimeInMilliseconds - ageInMilliseconds;
                    if (fileCanBeDeleted) {
                        resource.delete();
                        logger.debug("purgeOlderRestEasyFiles - deleted filename: {} form path:{}", resource.getName(), RESTEASY_TMP_PATH);
                    }
                }
            }
        }
        logger.debug("purgeOlderRestEasyFiles - completed");
    }



    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public void cleanupDirectoriesAndFiles(final String rootDirectoryPath, final long ageInMilliseconds) {
        final long currentTimeInMilliseconds = System.currentTimeMillis();
        final Resource resource = resources.getFileSystemResource(rootDirectoryPath);
        logger.debug("cleanupDirectoriesAndFiles - start check on  {}",rootDirectoryPath);
        // check if directory exist
        if (resource.exists()) {
            final Collection<Resource> subDirectories = resource.listDirectories();
            // check if there are some subdirectories
            if (subDirectories != null) {
                for (final Resource subDirectory : subDirectories) {
                    final String subDirName = subDirectory.getName();
                    resource.setURI(rootDirectoryPath.concat(File.separator).concat(subDirName));

                    final Collection<Resource> filesInSubDir = resource.listFiles();
                    boolean canDeleteSubDir = true;
                    for (final Resource file : filesInSubDir) {
                        resource.setURI(rootDirectoryPath.concat(File.separator).concat(subDirectory.getName()).concat(File.separator).concat(file.getName()));
                        if ( resource.getLastModificationTimestamp() > (currentTimeInMilliseconds - ageInMilliseconds)) {
                            canDeleteSubDir = false;
                            break;
                        }
                    }
                    if (canDeleteSubDir) {
                        final String filePath = rootDirectoryPath.concat(File.separator).concat(subDirName);
                        resource.setURI(filePath);
                        logger.debug("cleanupDirectoriesAndFiles - delete directory {} ",filePath);
                        resource.deleteDirectory();
                    }
                }
            }
        }
        logger.debug("cleanupDirectoriesAndFiles - end check on  {}",rootDirectoryPath);
    }

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public boolean exists(final String filePath) {
        return resources.getFileSystemResource(filePath).exists();
    }

    @TransactionAttribute(TransactionAttributeType.NOT_SUPPORTED)
    public String getOutputToFileDownloadDirectoryPath() {
        String path = System.getProperty(OUTPUT_TO_FILE_DOWNLOAD_FOLDER_PATH_PROPERTY, DEFAULT_OUTPUT_TO_FILE_DOWNLOAD_FOLDER_PATH);
        path = path.endsWith("/") ? path : path.concat("/");
        return path;
    }

    /*
     * P R I V A T E - M E T H O D S
     */
    private Enumeration<? extends InputStream> orderFileInputStreams(final List<String> orderedFileNames,
            final Collection<Resource> fileResources) {
        final Vector<InputStream> orderedFileResources = new Vector<InputStream>(fileResources.size());
        for (final String fileName : orderedFileNames) {
            final InputStream inputStream = getInputStreamForFile(fileResources.iterator(), fileName);
            if (inputStream != null) {
                orderedFileResources.add(inputStream);
            } else {
                systemRecorder.recordError("SCRIPT_ENGINE.FILE_READ_ERROR", ErrorSeverity.ERROR, null, "script-engine",
                        "Failed to get InputStream for file: " + fileName);
            }
        }
        return orderedFileResources.elements();
    }

    private InputStream getInputStreamForFile(final Iterator<Resource> iterator, final String fileName) {
        while (iterator.hasNext()) {
            final Resource resource = iterator.next();
            if (resource.getName().equals(fileName)) {
                return resource.getInputStream();
            }
        }
        return null;
    }

    private void writeFromInputStreamToOutputStream(final InputStream inputStream, final OutputStream outputStream) throws IOException {
        final byte[] buffer = new byte[BUFFER_SIZE];
        int bytesRead = 0;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            outputStream.write(buffer, 0, bytesRead);
        }
        outputStream.flush();
    }

    private boolean isTemporaryRestEasyFile( final String fileName, final boolean writeAccess) {
        return fileName.startsWith("m4j") && fileName.endsWith(".tmp") && writeAccess;
    }
}
