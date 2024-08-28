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
package com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.certificate;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.security.accesscontrol.EPredefinedRole;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.annotation.Authorize;

/**
 * This class is used to authorize Entity Certificate management operations.
 * 
 * @author tcsvath
 * 
 */
public class EntityCertificateManagementAuthorizationHandler {

    @Inject
    Logger logger;

    /**
     * Method used to authorize generate certificate for Entity
     */
    @Authorize(action = "create", resource = "entity_cert_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeGenerateCertificate() {
        logger.debug("User authorized to perform generate entity certificate");
    }

    /**
     * Method used to authorize listing/get of Entity certificates
     */
    @Authorize(action = "read", resource = "read_entityCerts", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeGetCertificate() {
        logger.debug("User authorized to perform get entity certificates");
    }

    /**
     * Method used to authorize update Entity certificate
     */
    @Authorize(action = "update", resource = "entity_cert_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeUpdateCertificate() {
        logger.debug("User authorized to perform update entity certificate");
    }

    /**
     * This method is used to check user authorization for generating Security Gateway Certificate.
     */
    @Authorize(action = "create", resource = "secgw_cert_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeGenerateSecGwCertificate() {
        logger.debug("User authorized to perform generate security gateway certificate");
    }
}
