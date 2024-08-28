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
package com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.profile;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.security.accesscontrol.EPredefinedRole;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.annotation.Authorize;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;

/**
 * This class is used to authorize external CA operations {@link CAEntity}
 * 
 */
public class ExternalCAAuthorizationHandler {

    @Inject
    private Logger logger;

    /**
     * Method used to authorize export external CA
     */
    @Authorize(action = "read", resource = "read_extCA", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeExportExternalCACeritifcate() {
        logger.debug("User is now authorized to perform export certificate for external CA Entity");
    }

    /**
     * Method used to authorize creation of external CA
     */
    @Authorize(action = "create", resource = "extCA_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeCreateExternalCA() {
        logger.debug("User is now authorized to perform create external CA entity");
    }

    /**
     * Method used to authorize listing/get of external CA
     */
    @Authorize(action = "read", resource = "read_extCA", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeGetExternalCA() {
        logger.debug("User is now authorized to perform listing of external CA entities");
    }

    /**
     * Method used to authorize updation of external CA
     */
    @Authorize(action = "update", resource = "extCA_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeUpdateExternalCA() {
        logger.debug("User is now authorized to perform update of external CA entity");
    }

    /**
     * Method used to authorize deletion of external CA
     */
    @Authorize(action = "delete", resource = "extCA_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeDeleteExternalCA() {
        logger.debug("User is now authorized to perform delete external CA entity");
    }
}
