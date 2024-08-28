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
package com.ericsson.oss.itpf.security.pki.manager.access.control.common.utils;

import javax.inject.Inject;

import com.ericsson.oss.itpf.sdk.context.ContextService;

/**
 * This class is used to check user context.
 * 
 * @author tcsvath
 * 
 */
public class ContextUtility {

    public static final String CONTEXT_KEY = "User.Name";
    public static final String CREDM_CONTEXT_VALUE = "CredentialManager";
    public static final String NSCS_CONTEXT_VALUE = "NSCS";
    public static final String INTERNAL_CONTEXT_VALUE = "Internal";

    @Inject
    private ContextService ctxService;

    /**
     * Method used to check credM user context.
     */
    public boolean isCredMOperation() {
        return ((ctxService.getContextData() != null) && (ctxService.getContextData().get(CONTEXT_KEY) != null) && ctxService.getContextData().get(CONTEXT_KEY).equals(CREDM_CONTEXT_VALUE));
    }

    /**
     * 
     * Method used to check NSCS user context.
     */
    public boolean isNSCSOperation() {
        return ((ctxService.getContextData() != null) && (ctxService.getContextData().get(CONTEXT_KEY) != null) && ctxService.getContextData().get(CONTEXT_KEY).equals(NSCS_CONTEXT_VALUE));
    }

    /**
     * 
     * Method used to check Internal context.
     */
    public boolean isInternalOperation() {
        return ((ctxService.getContextData() != null) && (ctxService.getContextData().get(CONTEXT_KEY) != null) && ctxService.getContextData().get(CONTEXT_KEY).equals(INTERNAL_CONTEXT_VALUE));
    }

    /**
     * Method used to set credM user context.
     */
    public void setCredMContext() {
        if (ctxService != null) {
            ctxService.setContextValue(CONTEXT_KEY, CREDM_CONTEXT_VALUE);
        }
    }

    /**
     * 
     * Method used to check NSCS user context.
     */
    public void setNSCSContext() {
        if (ctxService != null) {
            ctxService.setContextValue(CONTEXT_KEY, NSCS_CONTEXT_VALUE);
        }
    }

    /**
     * 
     * Method used to check Internal context.
     */
    public void setInternalContext() {
        if (ctxService != null) {
            ctxService.setContextValue(CONTEXT_KEY, INTERNAL_CONTEXT_VALUE);
        }
    }

}
