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
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;

/**
 * This class is used to authorize entity operations {@link Entity}
 * 
 * @author tcsvmeg
 * 
 */
public class EntityAuthorizationHandler {

    @Inject
    private Logger logger;

    /**
     * Method used to authorize import entities
     */
    @Authorize(action = "create", resource = "entity_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeImportEntities() {
        logger.debug("User is now authorized to perform creation of entity");
    }

    /**
     * Method used to authorize creation of entities
     */
    @Authorize(action = "create", resource = "entity_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeCreateEntity() {
        logger.debug("User is now authorized to perform create entity");
    }

    /**
     * Method used to authorize listing/get of entities
     */
    @Authorize(action = "read", resource = "read_entities", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeReadEntity() {
        logger.debug("User is now authorized to perform listing of entities");
    }

    /**
     * Method used to authorize updation of entities
     */
    @Authorize(action = "update", resource = "entity_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeUpdateEntity() {
        logger.debug("User is now authorized to perform update entity");
    }

    /**
     * Method used to authorize deletion of entities
     */
    @Authorize(action = "delete", resource = "entity_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeDeleteEntity() {
        logger.debug("User is now authorized to perform delete entity");
    }
    
    /**
     * Method used to authorize deletion of entities from taf
     */
    @Authorize(action = "delete", resource = "delete_taf_data", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeDeleteTAFEntity() {
        logger.debug("User is now authorized to perform delete entity from TAF");
    }
}