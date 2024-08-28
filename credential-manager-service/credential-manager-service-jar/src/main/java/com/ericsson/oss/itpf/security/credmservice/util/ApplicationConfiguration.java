/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2021
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.util;

public class ApplicationConfiguration {
    
    private ApplicationConfiguration() {
        //not called
    }
    
    /**
     * Method that return true if a platform is cENM false otherwise
     * 
     * @return if a platform is cENM or not
     */
    public static boolean isCENM() {
        final String readProperty = System.getProperty("configuration.env.cloud.deployment");
        if (readProperty != null && "TRUE".equals(readProperty)) {
            return true;
        }
        final String onCENM = System.getenv("CLOUD_DEPLOYMENT");
        return (onCENM != null && "TRUE".equals(onCENM));
    }
}
