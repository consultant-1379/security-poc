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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.common.eserviceref;

import javax.enterprise.context.ApplicationScoped;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.api.CRLManagementService;
import com.ericsson.oss.itpf.security.pki.core.crlmanagement.api.RevocationService;

@ApplicationScoped
public class CRLManagerEServiceProxy {

    @EServiceRef
    private CRLManagementService coreCRLManagementService;

    public CRLManagementService getCoreCRLManagementService() {
        return coreCRLManagementService;
    }

    @EServiceRef
    RevocationService revocationService;

    public RevocationService getRevocationService() {
        return revocationService;
    }

}
