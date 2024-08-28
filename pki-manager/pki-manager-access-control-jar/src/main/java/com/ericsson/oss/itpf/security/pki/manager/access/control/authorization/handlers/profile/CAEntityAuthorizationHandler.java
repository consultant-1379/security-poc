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
 * This class is used to authorize entity operations {@link CAEntity}
 * 
 * @author tcsvath
 * 
 */
public class CAEntityAuthorizationHandler {

    @Inject
    private Logger logger;

    /**
     * Method used to authorize import CA entities
     */
    @Authorize(action = "create", resource = "caEntity_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeImportEntities() {
        logger.debug("User is now authorized to perform inport caentities");
    }

    /**
     * Method used to authorize creation of CA entities
     */
    @Authorize(action = "create", resource = "caEntity_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeCreateEntity() {
        logger.debug("User is now authorized to perform create caentity");
    }

    /**
     * Method used to authorize listing/get of CA entities
     */
    @Authorize(action = "read", resource = "read_caEntities", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeReadEntity() {
        logger.debug("User is now authorized to perform listing of caentity");
    }

    /**
     * Method used to authorize updation of CA entities
     */
    @Authorize(action = "update", resource = "caEntity_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeUpdateEntity() {
        logger.debug("User is now authorized to perform update of caentity");
    }

    /**
     * Method used to authorize deletion of CA entities
     */
    @Authorize(action = "delete", resource = "caEntity_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeDeleteEntity() {
        logger.debug("User is now authorized to perform delete caentity");
    }
    
    /**
     * Method used to authorize deletion of entities from taf
     */
    @Authorize(action = "delete", resource = "delete_taf_data", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeDeleteTAFEntity() {
        logger.debug("User is now authorized to perform delete caentity from TAF");
    }
}
