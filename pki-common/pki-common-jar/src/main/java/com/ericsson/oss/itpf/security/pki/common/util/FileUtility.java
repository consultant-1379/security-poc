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
package com.ericsson.oss.itpf.security.pki.common.util;

import java.io.*;
import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;

import org.apache.commons.compress.archivers.tar.TarArchiveEntry;
import org.apache.commons.compress.archivers.tar.TarArchiveOutputStream;
import org.apache.commons.compress.compressors.gzip.GzipCompressorOutputStream;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.exception.InvalidFileExtensionException;

/**
 * This class handles all FileOperations.
 * 
 * @author tcsramc
 * 
 */
public class FileUtility {

    @Inject
    Logger logger;

    private FileUtility() {

    }

    static List<File> files = new ArrayList<File>();

    private static final Logger LOGGER = LoggerFactory.getLogger(FileUtility.class);

    /**
     * This method is used to fetch Files from the given directory.
     * 
     * @param directoryName
     *            Path from which Files needs to be fetched.
     * @return
     */
    public static List<File> listFiles(final String directoryName) {
        final File rootDirectory = new File(directoryName);
        final File[] listOfFiles = rootDirectory.listFiles();

        if (listOfFiles == null) {
            LOGGER.warn("No files found in the given directory:{}", ErrorMessages.FILE_NOT_FOUND_IN_PATH);
        }

        for (final File file : listOfFiles) {
            if (file.isDirectory()) {
                listFiles(file.getAbsolutePath());
            } else {
                files.add(file.getAbsoluteFile());
            }
        }
        return files;
    }

    /**
     * This methos is used to verify whether the file has the required file extension as supplied in fileExtensions
     * 
     * @param fileNameWithExtension
     *            Name of the file for which extension need to be verified
     * @param fileExtensions
     *            List of file extension that are allowed
     * @throws InvalidFileExtensionException
     *             This exception is thrown if any unsupported file extension encounters.
     */
    public static void verifyFileExtension(final String fileNameWithExtension, final List<String> fileExtensions) throws InvalidFileExtensionException {
        boolean isValid = false;
        for (final String eachExtension : fileExtensions) {
            if (fileNameWithExtension.endsWith(eachExtension)) {
                isValid = true;
            }
        }
        if (!isValid) {
            LOGGER.warn("Inconsistent file extension found. File does not have extension as : {} ", fileNameWithExtension);
            throw new InvalidFileExtensionException(ErrorMessages.UNEXPECTED_FILE_EXTENSION);
        }
    }

    /**
     * Creates tar.gz file contains all the selected certificates with the given type/extension.
     * 
     * @param files
     *            each file is a single certificate with the given type/extension.
     * @param zipfile
     *            tar.gz file name.
     * @return file tar.gz file contains all the selected certificates with the given type/extension
     * @throws IOException
     *             Thrown in case IOOperation failures.
     */
    public File createArchiveFile(final File[] files, final String zipFilePath) throws IOException {

        File tarFile = null;
        tarFile = new File(zipFilePath);
        BufferedInputStream bufferedInputStream = null;

        try(FileOutputStream fileOutputStream = new FileOutputStream(tarFile);BufferedOutputStream bufferedOutputStream = new BufferedOutputStream(fileOutputStream);GzipCompressorOutputStream gzipCompressorOutputStream = new GzipCompressorOutputStream(bufferedOutputStream);TarArchiveOutputStream tarArchiveOutputStream = new TarArchiveOutputStream(gzipCompressorOutputStream);) {


            for (int i = 0; i < files.length; i++) {

                final TarArchiveEntry entry = new TarArchiveEntry(files[i], files[i].getParentFile().toURI().relativize(files[i].toURI()).getPath());
                tarArchiveOutputStream.putArchiveEntry(entry);

                try(FileInputStream fileInputStream = new FileInputStream(files[i])) {
                    final int BUFFER = (int) files[i].length();
                    bufferedInputStream = new BufferedInputStream(fileInputStream, BUFFER);

                    int count;
                    final byte data[] = new byte[BUFFER];
                    while ((count = bufferedInputStream.read(data, 0, BUFFER)) != -1) {
                        tarArchiveOutputStream.write(data, 0, count);
                    }
                    bufferedInputStream.close();
                    tarArchiveOutputStream.closeArchiveEntry();
                }

            }


        } finally {

            if (bufferedInputStream != null) {
                bufferedInputStream.close();
            }
        }
        return tarFile;

    }

    /**
     * Delete files.
     * 
     * @param files
     *            each file is a single certificate with the given type/extension.
     */
    public void deleteFiles(final File[] files) {

        for (int index = 0; index < files.length; index++) {
            files[index].delete();
        }
    }

    /**
     * <p>
     * Method for getting FileName from Absolute File Path.
     * </p>
     *
     * @param filePath
     * @return name of the file
     */
    public String getFileNameFromAbsolutePath(final String filePath) {
        return (new File(filePath).getName());
    }

}
