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
package com.ericsson.oss.itpf.security.credmservice.impl;

import java.util.Properties;

import com.ericsson.oss.itpf.security.credmservice.util.PropertiesReader;

/**
 * DU: Solution for PKI External CA
 * 
 */
public class PKIExtCAManagementSolution {

    private final static String EXT_CA_NAME = "ext.ca.name";
    private final static String[] EXT_CA_NAME_DEFAULT_VALUE = { "VC_Root_CA_A1" };

    private final static String EXT_CA_FILES_PATH = "path.ext.ca.files";

    private final static String EXT_SUB_CA_NAMES = "ext.sub.ca.names";
    private final static String[] EXT_SUB_CA_NAMES_DEFAULT_VALUE = { "VC_Root_CA_A1", "VC_AE5_SubCA_A1_1_1", "VC_BD4_SubCA_A1_1_1",
            "VC_C84_SubCA_A1_1_1", "VC_CB4_SubCA_A1_1_1", "VC_CB7_SubCA_A1_1_1", "VC_CD3_SubCA_A1_1_1", "VC_D16_SubCA_A1_1_1", "VC_RBS_SubCA_A1_1",
            "VC_TU8_SubCA_A1_1_1" };

    private PKIExtCAManagementSolution() {
    } // Only static methods

    public static String[] getExtCAName() {
        String[] extCANames = null;
        final Properties props = PropertiesReader.getConfigProperties();
        if (props != null) {
            final String extCAName = props.getProperty(EXT_CA_NAME);
            if (extCAName != null) {
                extCANames = extCAName.split(",");
            } else {
                extCANames = EXT_CA_NAME_DEFAULT_VALUE;
            }
        }
        return extCANames;
    }

    public static String getExtCAPath() {
        final Properties props = PropertiesReader.getConfigProperties();
        if (props != null) {
            final String extCAPath = props.getProperty(EXT_CA_FILES_PATH);
            return extCAPath;
        }
        return null;
    }

    public static String[] getExtSubCAName(final String caName) {
        String[] extSubCANames = null;
        final Properties props = PropertiesReader.getConfigProperties();
        if (props != null) {
            final String extSubCAName = props.getProperty(EXT_SUB_CA_NAMES + "_" + caName);
            if (extSubCAName != null) {
                extSubCANames = extSubCAName.split(",");
            } else {
                extSubCANames = EXT_SUB_CA_NAMES_DEFAULT_VALUE;
            }
        }
        return extSubCANames;

    }
}
