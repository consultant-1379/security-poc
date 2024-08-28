/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.credmservice.impl;

import javax.enterprise.context.ApplicationScoped;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.api.ExtCACRLManagementService;

@ApplicationScoped
public class EServiceManager {

    @EServiceRef
    ExtCACRLManagementService pkiExtCACRLManager;

    /**
     * @return the pkiExtCACRLManager
     */
    public ExtCACRLManagementService getPkiExtCACRLManager() {
        return pkiExtCACRLManager;
    }
}
