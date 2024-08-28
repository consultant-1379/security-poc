/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.access.control.authorization;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.crl.CRLManagementAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.utils.ContextUtility;

public class CRLManagementAuthorizationManager {

    @Inject
    public Logger logger;

    @Inject
    SystemRecorder systemRecorder;

    @Inject
    private ContextUtility contextUtility;

    @Inject
    CRLManagementAuthorizationHandler crlManagementAuthorizationHandler;

    /**
     * Method used to authorize revoke entity Certificate.
     */
    public void authorizeGetCRL() {

        logger.info("Authorizing get CRL");

        if (!contextUtility.isCredMOperation()) {
            crlManagementAuthorizationHandler.authorizeGetCRL();
        }
    }

}
