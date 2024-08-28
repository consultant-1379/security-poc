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
package com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.rest;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.security.accesscontrol.EPredefinedRole;
import com.ericsson.oss.itpf.sdk.security.accesscontrol.annotation.Authorize;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;

/**
 * This class is used to authorize list certificate operations {@link Certificate}
 * 
 * @author tcsgoma
 * 
 */
//TODO TORF-111002: RBAC-remove duplicate classes
public class CertificateManagementAuthorizationHandler {

    @Inject
    Logger logger;

    /**
     * Method used to authorize listing/get of CA certificates
     */
    @Authorize(action = "read", resource = "read_caCerts", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeListCACerts() {
        logger.debug("User is now authorized to perform listing of caentity");
    }

    /**
     * Method used to authorize listing/get of Entity certificates
     */
    @Authorize(action = "read", resource = "read_entityCerts", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeListEntityCerts() {
        logger.debug("User is now authorized to perform listing of entities");
    }
}
