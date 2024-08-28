/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmservice.impl;

import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.sdk.context.ContextService;

public class RBACManagement {

    private static final Logger log = LoggerFactory.getLogger(RBACManagement.class);

    private static String USER_NAME = "User.Name";
    private static String USER_NAME_VALUE = "CredentialManager";
    private static String TORID_USER ="X-Tor-UserID";
    
    private RBACManagement() {
    }

    // return boolean only for test-purpose
    public static boolean injectUserName(final ContextService ctxService) {

    
      if (ctxService != null) {
            ctxService.setContextValue(USER_NAME, USER_NAME_VALUE);

            if (null == ctxService.getContextValue(TORID_USER) ) {
                ctxService.setContextValue(TORID_USER, USER_NAME_VALUE);
                log.debug ("Found TORID_USER empty Set CredentialManager context");
            }
            else
            {
                log.debug ("Found TORID_USER Full");
            }

            log.debug("Context Service Injection done!!!");
            return true;

        } 
        log.error("Context Service Injection failed");
        return false;
    }
}
