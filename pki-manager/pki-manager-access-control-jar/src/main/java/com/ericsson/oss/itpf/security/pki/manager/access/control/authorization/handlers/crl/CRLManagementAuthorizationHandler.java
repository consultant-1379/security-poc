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

public class CRLManagementAuthorizationHandler {

    @Inject
    Logger logger;

    /**
     * Method used to authorize read/get CRLs
     */
    @Authorize(action = "read", resource = "read_crls", role = { EPredefinedRole.SECURITYADMIN, EPredefinedRole.ADMINISTRATOR })
    public void authorizeGetCRL() {
        logger.debug("User authorized to perform read CRLs");
    }

}
