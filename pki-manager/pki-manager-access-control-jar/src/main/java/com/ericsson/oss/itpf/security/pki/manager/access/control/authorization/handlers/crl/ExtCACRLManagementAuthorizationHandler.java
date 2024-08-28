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
package com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.crl;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.security.accesscontrol.EPredefinedRole;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.annotation.Authorize;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;

/**
 * This class is used to authorize external CA operations {@link CAEntity}
 * 
 */
public class ExtCACRLManagementAuthorizationHandler {

    @Inject
    private Logger logger;

    /**
     * Method used to authorize updation of external CA
     */
    @Authorize(action = "update", resource = "extCA_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeUpdateExternalCA() {
        logger.debug("User is now authorized to perform update of external CA entity");
    }

    /**
     * Method used to authorize read of external CA
     */
    @Authorize(action = "read", resource = "read_extCRL", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeGetExternalCRLInfo() {
        logger.debug("User is now authorized to perform listing external CRL info");
    }

    /**
     * Method used to authorize deletion of external CA
     */
    @Authorize(action = "delete", resource = "extCA_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeDeleteExternalCRLInfo() {
        logger.debug("User is now authorized to perform delete external CRL info");
    }
}
