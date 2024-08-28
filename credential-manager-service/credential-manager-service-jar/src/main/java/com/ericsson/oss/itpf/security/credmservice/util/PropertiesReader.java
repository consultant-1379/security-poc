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
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.services.security.pkimock.exception.MockCertificateServiceException;

/**
 * This class manages the configuration property parameters used in credential manager service. A property file is loaded with a location precedence
 * rule: 1st location - the file is searched with full path 2nd location - the file is searched into the default credential manager service
 * configuration dir /ericsson/credm/service/data 3rd location - the file is searched into the /tmp directory 4th location - the file is searched into
 * credential-manager-service-jar module.
 */
public final class PropertiesReader {

    private static final Logger log = LoggerFactory.getLogger(PropertiesReader.class);
    private static final String DEFAULT_PROPERTY_FILE_NAME = "credmservice.properties";
    private static final String DEFAULT_CREDM_SERVICE_CONFIGURATION_DIR = "/ericsson/credm/service/data/";
    private static Map<String, Properties> propertiesMap = new HashMap<String, Properties>();

    private PropertiesReader() {
    }

    /**
     * Return the properties content of the default credential manager service configuraiton file. Usually, this file is included into the
     * credential-manager-service-jar module.
     *
     * @return Properties
     */
    public static Properties getConfigProperties() {
        return getProperties(DEFAULT_PROPERTY_FILE_NAME);
    }

    /**
     * Return the property content of the file @param filename. The file is read the first time that the method getProperties is invoked.
     *
     * @param filename
     * @return
     */
    public static synchronized Properties getProperties(final String filename) {

    	Properties ret = null;

        if (propertiesMap.containsKey(filename.trim().toLowerCase())) {
            ret = propertiesMap.get(filename.trim().toLowerCase());
        } else {

            ret = getPropertiesFromFileSystem(filename);
        }
        return ret;
    }

	/**
	 * @param filename
	 * @param ret
	 * @return
	 */
	public static synchronized Properties getPropertiesFromFileSystem(final String filename) {
		InputStream input = null;
		Properties ret = null;
		
		log.info("looking for property file.... " + filename);
		try {
		    // firstly assumed that the file has a full path
		    input = readFromFullPath(filename);

		    // secondly assumed that the file is in ../conf/
		    if (input == null) {
		        input = readFromDefaultConfigurationDir(filename);
		    }

		    // thirdly assumed that the file is in /tmp/
		    if (input == null) {
		        input = readFromTmp(filename);
		    }
		  
		    // fourthly assumed that that the file is in the jar
		    if (input == null) {
		        input = readFromJar(filename);
		    }

		    if (input != null) {
		        ret = new Properties();
		        // load a properties file from class path, inside static method
		        ret.load(input);
		        propertiesMap.put(filename.trim().toLowerCase(), ret);
		    } else {
		        throw new MockCertificateServiceException("Properties file not found: " + filename);
		    }
		} catch (final Exception e) {
		    throw new MockCertificateServiceException("Error retrieving properties file : " + filename);
		} finally {
		    if (input != null) {
		        try {
		            input.close();
		        } catch (final IOException e) {
		            log.error(e.getMessage());
		        }
		    }
		}
    //   }
		return ret;
	}

    /**
     * @param filename
     * @return
     */
    private static InputStream readFromJar(final String filename) {
        InputStream input;
        String filteredFilename = filename;
        if (filteredFilename != null && filteredFilename.length() > 1 && filteredFilename.charAt(0) == File.separatorChar) {
            filteredFilename = filteredFilename.substring(1, filteredFilename.length());
        }
        input = Thread.currentThread().getContextClassLoader().getResourceAsStream(filteredFilename);
        log.info("found file " + filteredFilename + " from classpath as resource.");
        return input;
    }

    /**
     * @param filename
     * @return
     */
    private static InputStream readFromTmp(final String filename) {
        InputStream input = null;
        try {
            final File inputfile = new File("/tmp/" + filename);
            if (inputfile != null && inputfile.exists()) {
                input = new FileInputStream(inputfile); // NOSONAR
                log.info("found file " + inputfile + " from tmp path.");
            }
        } catch (final Exception e) {
            input = null;
        }
        return input;
    }

    /**
     * @param filename
     * @return
     */
    private static InputStream readFromDefaultConfigurationDir(final String filename) {
        InputStream input = null;
        try {
            final File inputfile = new File(DEFAULT_CREDM_SERVICE_CONFIGURATION_DIR + filename);
            if (inputfile != null && inputfile.exists()) {
                input = new FileInputStream(inputfile); // NOSONAR
                log.info("found file " + inputfile + " from tmp path.");
            }
        } catch (final Exception e) {
            input = null;
        }
        return input;
    }

    /**
     * @param filename
     * @return
     */
    //    private static InputStream readFromParentConf(final String filename) {
    //        InputStream input = null;
    //        try {
    //            File dir = null;
    //            File current = null;
    //            try {
    //                current = new File(PropertiesReader.class.getProtectionDomain().getCodeSource().getLocation().toURI());
    //                if (current.isDirectory()) {
    //                    dir = current;
    //                }
    //                if (current.isFile()) {
    //                    dir = new File(current.getParent());
    //                }
    //
    //            } catch (final URISyntaxException e1) {
    //
    //            }
    //            File inputfile = null;
    //            if (dir != null) {
    //                inputfile = new File(dir.getParent() + "/conf/" + filename);
    //            }
    //            if (inputfile != null && inputfile.exists()) {
    //                input = new FileInputStream(inputfile);
    //                log.info("found file " + inputfile + " from /conf/ path.");
    //            }
    //        } catch (final Exception ex) {
    //            input = null;
    //        }
    //        return input;
    //    }

    /**
     * @param filename
     * @return
     */
    private static InputStream readFromFullPath(final String filename) {
        InputStream input = null;
        try {
            final File inputfile = new File(filename);
            if (inputfile != null && inputfile.exists()) {
                input = new FileInputStream(inputfile); // NOSONAR
                log.info("found file " + inputfile + " from real path.");
            }
        } catch (final Exception e) {
            input = null;
        }
        return input;
    }
}
