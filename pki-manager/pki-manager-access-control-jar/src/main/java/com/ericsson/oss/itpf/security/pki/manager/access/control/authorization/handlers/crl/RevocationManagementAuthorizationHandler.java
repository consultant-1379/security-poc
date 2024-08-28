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

/**
 * This class is used to authorize Revocation Management Operations.
 * 
 * @author tcsvath
 * 
 */
public class RevocationManagementAuthorizationHandler {

    @Inject
    private Logger logger;

    /**
     * Method used to authorize revoke CAEntity certificate
     */
    @Authorize(action = "update", resource = "caEntity_cert_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeRevokeCACertificate() {
        logger.debug("User authorized to revoke caentity certificate");

    }

    /**
     * Method used to authorize revoke entity certificate
     */
    @Authorize(action = "update", resource = "entity_cert_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeRevokeEntityCertificate() {
        logger.debug("User authorized to revoke entity certificate");

    }
}
