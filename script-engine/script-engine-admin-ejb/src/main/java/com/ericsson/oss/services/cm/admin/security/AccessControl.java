/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2019
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.services.cm.admin.security;

import com.ericsson.oss.itpf.sdk.security.accesscontrol.ESecurityAction;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.ESecurityResource;

public enum AccessControl {
    APP_PARAM_UPDATE("config_app_param", "update"),
    APP_PARAM_VIEW("config_app_param", "read");

    private final ESecurityResource resource;
    private final ESecurityAction action;

    AccessControl(final String resource, final String action) {
        this.resource = new ESecurityResource(resource);
        this.action = new ESecurityAction(action);
    }

    public ESecurityResource getResource() {
        return resource;
    }

    public ESecurityAction getAction() {
        return action;
    }
}