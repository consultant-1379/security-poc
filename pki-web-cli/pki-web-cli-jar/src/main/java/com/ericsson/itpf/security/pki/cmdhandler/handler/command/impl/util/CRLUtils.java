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
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util;

import java.io.*;
import java.util.List;
import java.util.zip.ZipEntry;
import java.util.zip.ZipOutputStream;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLServiceException;

/**
 * Utility to convert the bytes in to zip file and again converting it to bytes Array.
 * 
 * @author xsaufar
 * 
 */

public class CRLUtils {

    @Inject
    Logger logger;

    /**
     * This method returns array of files, each containing CRL.
     * 
     *
     * @param cRLList
     *            list contains multiple certificate.
     * @return File tar.gz file containing all the selected certificates each one with the given type/extension for multiple certificates.
     * @throws IOException
     *
     */
    public File[] createCRLFiles(final List<CRLInfo> cRLList, final String cAName) throws IOException {


        File[] files = new File[cRLList.size()];
        int count = 0;

            for (CRLInfo crlInfo : cRLList) {

                final String crlTempPath = Constants.TMP_DIR + Constants.FILE_SEPARATOR + cAName + "_" + crlInfo.getIssuerCertificate().getSerialNumber() + count + Constants.CRL_EXTENSION;
                 final File crlFile = new File(crlTempPath);

                 try(FileOutputStream fos = new FileOutputStream(crlFile)) {

		                fos.write(crlInfo.getCrl().getX509CRLHolder().getCrlBytes());

		                files[count] = crlFile;
		                count++;
             }
            }
        return files;
    }

    /**
     * Creates tar.gz file contains all the selected CRL(s) with the given type/extension.
     *
     * @param files
     *            each file is a single certificate with the given type/extension.
     * @param zipfile
     *            tar.gz file name.
     * @return file tar.gz file contains all the selected CRL(s)
     * @throws IOException
     * @throws CRLServiceException
     *             Thrown in case file generation failures.
     */
    public File createZipFile(final File[] files, final String zipfile) throws CRLServiceException {

    	    try(ZipOutputStream zipOutputStream = new ZipOutputStream(new FileOutputStream(zipfile))) {
			logger.debug("Number of selected crls {} ", files.length);
			int bytes_read;

			for (int fileCount = 0; fileCount < files.length; fileCount++) {
				if (files[fileCount].isDirectory()) {
					continue;
				}
				try(FileInputStream fileInputStream = new FileInputStream(files[fileCount])){
					zipOutputStream.putNextEntry(new ZipEntry(files[fileCount].getName()));
					final int BUFFER = (int) files[fileCount].length();
					final byte[] buffer = new byte[BUFFER];
					while ((bytes_read = fileInputStream.read(buffer)) != -1) {
						zipOutputStream.write(buffer, 0, bytes_read);
					}
				}
			}
			return new File(zipfile);
		} catch (IOException ioException) {
			logger.error(PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR, ioException);
			throw new CRLServiceException(PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR + ioException.getMessage());
		}
    }

    /**
     * Converting the zip file into the byte Array.
     *
     *
     * @param file
     *            tar.gz file.
     * @return byte[] byte array contains all the CRL(s) bytes.
     * @throws IOException
     *
     */

    public byte[] convertFiletoByteArray(final File file) throws IOException {

        final byte[] fileBytes = new byte[(int) file.length()];
        try(FileInputStream fileInputStream = new FileInputStream(file);
                DataInputStream data = new DataInputStream(fileInputStream);) {
            data.readFully(fileBytes);

        }
        return fileBytes;
    }

}
