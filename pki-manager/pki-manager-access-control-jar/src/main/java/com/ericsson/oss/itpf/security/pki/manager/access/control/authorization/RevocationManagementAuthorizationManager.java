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
package com.ericsson.oss.itpf.security.pki.manager.access.control.authorization;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.handlers.crl.RevocationManagementAuthorizationHandler;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.utils.ContextUtility;

/**
 * This class is used to authorize Revocation Management Operations.
 * 
 * @author tcsvath
 * 
 */
public class RevocationManagementAuthorizationManager {

    @Inject
    public Logger logger;

    @Inject
    SystemRecorder systemRecorder;

    @Inject
    private ContextUtility contextUtility;

    @Inject
    RevocationManagementAuthorizationHandler revocationManagementAuthorizationHandler;

    /**
     * Method used to authorize revoke entity Certificate.
     */
    public void authorizeRevokeEntityCertificate() {
        logger.debug("Authorizing revoke entity certificate");

        if (!(contextUtility.isNSCSOperation() || contextUtility.isInternalOperation() || contextUtility.isCredMOperation())) {
            revocationManagementAuthorizationHandler.authorizeRevokeEntityCertificate();
        }
    }

    /**
     * Method used to authorize revoke CA Certificate.
     */
    public void authorizeRevokeCACertificate() {
        logger.debug("Authorizing revoke ca certificate");

        if (!(contextUtility.isNSCSOperation() || contextUtility.isInternalOperation() || contextUtility.isCredMOperation())) {
            revocationManagementAuthorizationHandler.authorizeRevokeCACertificate();
        }
    }
}
