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
package com.ericsson.oss.itpf.security.credmsapi.business.utils;

import java.io.File;
import java.io.FileInputStream;
import java.io.FileNotFoundException;
import java.io.IOException;
import java.io.InputStream;
import java.net.URISyntaxException;
import java.util.HashMap;
import java.util.Map;
import java.util.Properties;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ConfigurationException;

public final class PropertiesReader {
	private static final Logger LOG = LogManager.getLogger(PropertiesReader.class);
	
    private static Map<String, Properties> propertiesMap = new HashMap<String, Properties>();

    //	public PropertiesReader() {
    //
    //	}
    
    // keys for the properties
    public static final String ADDRESS = "address";
    public static final String ADDRESS_SEPARATOR = ",";   
 
    public static final String PEM_ENCRYPTION = "pemEncryption";
    public static final String PEM_ENCRYPTION_DEFAULT = "AES-128-CFB";
    
    /**
     * getProperty 
     * 
     * allow to retrieve a property from the config.property file
     * 
     * @param propertyName
     * @return
     * @throws ConfigurationException 
     */
    public static String getProperty(final String propertyName, final String propertyDefault) throws ConfigurationException {
        
        // Retrieve the properties
        final Properties props = PropertiesReader.getProperties(PropertiesReader.getConfigFile());
        return props.getProperty(propertyName, propertyDefault);
        
    }

    public static String getConfigFile() {
        return "config.properties";
    }

    public static Properties getConfigProperties() throws ConfigurationException {
        return getProperties(getConfigFile());
    }

    public static synchronized Properties getProperties(final String filename) throws ConfigurationException {

        if (propertiesMap.containsKey(filename.trim().toLowerCase())) {
            return propertiesMap.get(filename.trim().toLowerCase());
        }

        Properties prop = null;
        InputStream input = null;
        File inputfile = null;

        try {
            // firstly assumed that the file has a full path
            try {
                inputfile = new File(filename);
                input = new FileInputStream(inputfile);
            } catch (final Exception e) {
                //do nothing and continue
            }

            // secondly assumed that the file is in ../conf/
            try {
                if (input == null) {
                    File dir = null;
                    File current = null;
                    try {
                        current = new File(PropertiesReader.class.getProtectionDomain().getCodeSource().getLocation().toURI());
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
                    if (inputfile.exists()) {
                        input = new FileInputStream(inputfile);
                    }
                }
            } catch (final Exception ex) {
                input = null;
            }

            // thirdly assumed that that the file is in the jar
            if (input == null) {
                input = PropertiesReader.class.getClassLoader().getResourceAsStream(filename);
                // Logger.getLogger().debug(
                // "PropertiesReader: read file " + filename
                // + " from classpath as resource.");
            }
            prop = new Properties();
            // load a properties file from class path, inside static method
            prop.load(input);
            propertiesMap.put(filename.trim().toLowerCase(), prop);
        } catch (final Exception e) {
            LOG.error(ErrorMsg.API_ERROR_BUSINESS_UTILS_CHECK_PROPERTIESFILE,filename);
            throw new ConfigurationException();
        } finally {
            if (input != null) {
                try {
                    input.close();
                } catch (final IOException e) {
                	LOG.error(ErrorMsg.API_ERROR_BUSINESS_UTILS_CLOSE_PROPERTIESFILE,filename);
                    // Logger.getLogger().error(e.getMessage());
                }
            }
        }
        return prop;
    }
    
}
