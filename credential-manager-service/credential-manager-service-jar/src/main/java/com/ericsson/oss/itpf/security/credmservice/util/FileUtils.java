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
package com.ericsson.oss.itpf.security.credmservice.util;

import java.io.File;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class FileUtils {

    private static final Logger log = LoggerFactory.getLogger(FileUtils.class);

    private FileUtils() {
    } // Only static methods

    public static void delete(final String pathFile) {
        final File file = new File(pathFile);
        if (file.delete()) {
            log.info("File " + pathFile + " deleted.");
        } else {
            log.error(("File " + pathFile + " delete failed."));
        }
    }

    public static boolean isExist(final String pathFile) {
        final File file = new File(pathFile);
        
        return file.exists(); 
       
    }

    public static void renameTo(final String pathFile, final String newPathFile) {
        final File file = new File(pathFile);
        final File file2 = new File(newPathFile);
        if (file.renameTo(file2)) {
            log.info("File " + pathFile + " renamed to " + newPathFile + ".");
        } else {
            log.error(("File " + pathFile + " rename failed."));
        }
    }
}
