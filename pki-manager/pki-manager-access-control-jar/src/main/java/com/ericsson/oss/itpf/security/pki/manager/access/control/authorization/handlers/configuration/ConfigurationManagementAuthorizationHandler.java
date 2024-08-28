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
package com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.configuration;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.security.accesscontrol.EPredefinedRole;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.annotation.Authorize;

/**
 * This class is used to authorize Configuration management operations.
 * 
 * @author tcsvath
 * 
 */
public class ConfigurationManagementAuthorizationHandler {

    @Inject
    private Logger logger;

    /**
     * Method used to authorize listing/get of algorithms
     */
    @Authorize(action = "read", resource = "read_algorithms", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeGetAlgorithm() {
        logger.debug("User authorized to perform listing/get of algorithms");

    }

    /**
     * Method used to authorize enable/disable algorithms
     */
    @Authorize(action = "update", resource = "update_algorithms", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeUpdateAlgorithm() {

        logger.debug("User authorized to enable/disable algorithms");

    }

    /**
     * Method used to authorize create category
     */
    @Authorize(action = "create", resource = "entity_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeCreateEntityCategory() {
        logger.debug("User authorized to create category");

    }

    /**
     * Method used to authorize update category
     */
    @Authorize(action = "update", resource = "entity_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeUpdateEntityCategory() {

        logger.debug("User authorized to update category");

    }

    /**
     * Method used to authorize delete category
     */
    @Authorize(action = "delete", resource = "entity_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeDeleteEntityCategory() {
        logger.debug("User authorized to delete category");

    }

    /**
     * Method used to authorize list/get categories
     */
    @Authorize(action = "read", resource = "read_entities", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeGetEntityCategory() {

        logger.debug("User authorized to list/get categories");

    }

    /**
     * Method used to authorize get custom configuration
     */
    @Authorize(action = "read", resource = "read_entities", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeGetCustomConfiguration() {
        logger.debug("User authorized to list/get custom configuration");
    }

    /**
     * Method used to authorize update custom configuration
     */
    @Authorize(action = "update", resource = "entity_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeUpdateCustomConfiguration() {
        logger.debug("User authorized to update custom configuration");
    }

    /**
     * Method used to authorize create custom configuration
     */
    @Authorize(action = "create", resource = "entity_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeCreateCustomConfiguration() {
        logger.debug("User authorized to create custom configuration");
    }

    /**
     * Method used to authorize delete custom configuration
     */
    @Authorize(action = "delete", resource = "entity_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeDeleteCustomConfiguration() {
        logger.debug("User authorized to delete custom configuration");
    }

}
