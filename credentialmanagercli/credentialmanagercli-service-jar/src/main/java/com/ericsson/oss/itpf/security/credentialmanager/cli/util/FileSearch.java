/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credentialmanager.cli.util;

import java.io.File;
import java.net.URISyntaxException;

public final class FileSearch {

    private FileSearch() {

    }

    /**
     * 
     * @param filename
     * @return
     */
    public static synchronized File getFile(final String filename) {

        File inputfile = null;

        //firstly assumed that the file has a full path
        try {
            inputfile = new File(filename);

        } catch (final Exception e) {
            inputfile = null;

        }

        //secondly assumed that the file is in ../conf/
        try {
            if (inputfile == null || !inputfile.exists()) {
                File dir = null;
                File current = null;
                try {
                    current = new File(FileSearch.class.getProtectionDomain().getCodeSource().getLocation().toURI());
                    if (current.isDirectory()) {
                        dir = current;
                    }
                    if (current.isFile()) {
                        dir = new File(current.getParent());
                    }

                } catch (final URISyntaxException e1) {

                }
                if (dir != null) {
                    inputfile = new File(dir.getParent() + "/conf/" + filename);
                }

            }
        } catch (final Exception ex) {
            inputfile = null;
        }
        if (inputfile == null) {
            inputfile = new File(FileSearch.class.getClassLoader().getResource(filename).getPath());
        }

        return inputfile;

    }
}
