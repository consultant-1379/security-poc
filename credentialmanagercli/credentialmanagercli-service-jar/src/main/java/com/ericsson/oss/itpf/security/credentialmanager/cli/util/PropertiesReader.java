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

import java.io.*;
import java.net.URISyntaxException;
import java.util.*;

import com.ericsson.oss.itpf.security.credentialmanager.cli.exception.CredentialManagerException;


public final class PropertiesReader {
    private static Map<String, Properties> propertiesMap = new HashMap<String, Properties>();

    private PropertiesReader() {

    }

    public static String getConfigFile() {
        return "config-cli.properties";
    }

    public static Properties getConfigProperties() {
        return getProperties(getConfigFile());
    }

    public static synchronized Properties getProperties(final String filename) {

        if (propertiesMap.containsKey(filename.trim().toLowerCase())) {
            return propertiesMap.get(filename.trim().toLowerCase());
        }

        Properties prop = null;
        InputStream input = null;
        File inputfile = null;

        try {
            //firstly assumed that the file has a full path
            try {
                inputfile = new File(filename);
                if (inputfile != null && inputfile.exists()) {
                    input = new FileInputStream(inputfile);
                    Logger.getLogger().debug("PropertiesReader: read file " + inputfile + " from real path.");
                }
            } catch (final Exception e) {
                input = null;

            }

            //secondly assumed that the file is in ../conf/ (or in /resourses for debug)
            try {
                if (input == null) {
                    File dir = null;
                    File current = null;
                    try {
                        current = new File(PropertiesReader.class.getProtectionDomain().getCodeSource().getLocation()
                                .toURI());
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
                    if (inputfile != null && inputfile.exists()) {
                        input = new FileInputStream(inputfile);
                        Logger.getLogger().debug("PropertiesReader: read file " + inputfile + " from /conf/ path.");
                    }
                    else {
                    	// try resources
                    	inputfile = new File(dir.getParent() + "/resources/" + filename);
                    	if (inputfile != null && inputfile.exists()) {
                            input = new FileInputStream(inputfile);
                            Logger.getLogger().debug("PropertiesReader: read file " + inputfile + " from resources path.");
                        } else {
                            // try default dir src/main/resources
                            inputfile = new File(dir.getParent() + "/../../credentialmanagercli-jar/src/main/resources/" + filename);
                            if (inputfile != null && inputfile.exists()) {
                                    input = new FileInputStream(inputfile);
                                    Logger.getLogger().debug("PropertiesReader: read file " + inputfile + " from credentialmanagercli-jar/src/main/resources path.");
                            }
                        }
                    }
                }
            } catch (final Exception ex) {
                input = null;
            }

            //thirdly assumed that that the file is in the jar
            if (input == null) {
                input = PropertiesReader.class.getClassLoader().getResourceAsStream(filename);
                Logger.getLogger().debug("PropertiesReader: read file " + filename + " from classpath as resource.");
            }
            prop = new Properties();
            // load a properties file from class path, inside static method
            prop.load(input);
            propertiesMap.put(filename.trim().toLowerCase(), prop);
        } catch (final Exception e) {
            Logger.getLogger().error("Properties file not found: " + filename);
            throw new CredentialManagerException("Properties file not found: " + filename, e);

        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (final IOException e) {
                    Logger.getLogger().error(e.getMessage());
                }
            }
        }
        return prop;
    }
}
