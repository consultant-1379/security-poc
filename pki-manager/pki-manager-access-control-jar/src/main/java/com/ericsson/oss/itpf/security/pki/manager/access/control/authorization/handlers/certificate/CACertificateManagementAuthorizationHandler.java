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
 * This class is used to authorize CAEntity Certificate management operations.
 * 
 * @author tcsvath
 * 
 */
public class CACertificateManagementAuthorizationHandler {

    @Inject
    private Logger logger;

    /**
     * Method used to authorize generate certificate for CAEntity
     */
    @Authorize(action = "create", resource = "caEntity_cert_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeGenerateCertificate() {

        logger.debug("User authorized to perform generate caentity certificate");

    }

    /**
     * Method used to authorize listing/get of CA certificates
     */
    @Authorize(action = "read", resource = "read_caCerts", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeGetCertificate() {
        logger.debug("User authorized to perform listing caentity certificates");

    }

    /**
     * Method used to authorize update CAEntity certificate
     */
    @Authorize(action = "update", resource = "caEntity_cert_mgmt", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeUpdateCertificate() {

        logger.debug("User authorized to perform update caentity certificate");

    }

}
