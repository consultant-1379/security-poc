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
package com.ericsson.oss.itpf.security.credmservice.impl;

import java.util.Properties;

import com.ericsson.oss.itpf.security.credmservice.util.PropertiesReader;

public class PKIMockManagement {

    private final static String MOCK_PROFILE = "mock.profile";
    private final static String MOCK_CERTIFICATE = "mock.certificate";
    private final static String MOCK_ICACRL = "mock.icacrl";
    private final static String MOCK_ECACRL = "mock.ecacrl";
    private final static String MOCK_CVN = "mock.cvn";

    private PKIMockManagement() {
    } // Only static methods

    public static boolean useMockProfileManager() {
        return useMock(MOCK_PROFILE);
    }

    public static boolean useMockCertificateManager() {
        return useMock(MOCK_CERTIFICATE);
    }
    
    public static boolean useMockIntCACrlManager() {
        return useMock(MOCK_ICACRL);
    }

    public static boolean useMockExtCACrlManager() {
        return useMock(MOCK_ECACRL);
    }
    
    public static boolean useMockCvn() {
        return useMock(MOCK_CVN);
    }

    private static boolean useMock(final String name) {

        boolean ret = false;
        final Properties props = PropertiesReader.getConfigProperties();
        if ("true".equals(props.getProperty(name))) {
            ret = true;
        }
        return ret;
    }
}
