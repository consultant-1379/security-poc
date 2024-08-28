/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
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

import javax.management.AttributeNotFoundException;
import javax.management.InstanceNotFoundException;
import javax.management.MBeanException;
import javax.management.MalformedObjectNameException;
import javax.management.ReflectionException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

public class StorageFilesInformation {

    private static final Logger log = LoggerFactory.getLogger(StorageFilesInformation.class);

    private static final String JBOSS_EJB_STORES_PATH_DEFAULT = "/ericsson/credm/service/data/certs";

    private static final String USE_JBOSS_CONFIG_DIR_AS_EJB_STORES_PATH_PROPERTY_NAME = "jboss.config.as.keystore.path";

    public static final String FILE_PROPERTIES = "/ericsson/credm/service/data/config.properties";
    static final String JBOSS_EJB_KEY_STORE_FILE_NAME = "jbossEjbKeyStoreFileName";
    public static final String JBOSS_EJB_KEY_STORE_FILE_DEFAULT = "CredMService.jks";
    static final String JBOSS_EJB_TRUST_STORE_FILE_NAME = "jbossEjbTrustStoreFileName";
    public static final String JBOSS_EJB_TRUST_STORE_FILE_DEFAULT = "CredMServiceTS.jks";

    public static String outputPath = null;

    private StorageFilesInformation() {
    } //Only static methods

    /**
     * Retrieves the Jboss keystore filepath
     *
     * @return the full path keystore filename
     */
    public static String getKeystoreFilePath() {
        if (outputPath == null) {
            outputPath = getJBossEJBKeystoresPath();
        }
        final String keystoreFileName = PropertiesReader.getProperties(FILE_PROPERTIES).getProperty(JBOSS_EJB_KEY_STORE_FILE_NAME);
        if (keystoreFileName != null) {
            return outputPath + File.separator + keystoreFileName;
        } else {
            return outputPath + File.separator + JBOSS_EJB_KEY_STORE_FILE_DEFAULT;
        }
    }

    /**
     * Retrieves the Jboss truststore filepath
     *
     * @return the full path truststore filename
     */
    public static String getTruststoreFilePath() {
        if (outputPath == null) {
            outputPath = getJBossEJBKeystoresPath();
        }
        final String truststoreFileName = PropertiesReader.getProperties(FILE_PROPERTIES).getProperty(JBOSS_EJB_TRUST_STORE_FILE_NAME);
        if (truststoreFileName != null) {
            return outputPath + File.separator + truststoreFileName;
        } else {
            return outputPath + File.separator + JBOSS_EJB_TRUST_STORE_FILE_DEFAULT;
        }
    }

    /**
     *
     */
    private static String getJBossEJBKeystoresPath() {
        String ret = "";
        final String prop = PropertiesReader.getProperties(FILE_PROPERTIES).getProperty(USE_JBOSS_CONFIG_DIR_AS_EJB_STORES_PATH_PROPERTY_NAME);

        if ("true".equals(prop)) {
            try {
                ret = MBeanManager.getJBossConfigPath();
            } catch (MalformedObjectNameException | AttributeNotFoundException | InstanceNotFoundException | MBeanException | ReflectionException e) {
                log.error("Cannot retrieve Jboss config path");
                e.printStackTrace();
            }
        } else {
            ret = JBOSS_EJB_STORES_PATH_DEFAULT;
        }
        return ret;
    }

}
