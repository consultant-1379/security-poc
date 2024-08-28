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

import java.util.List;

import javax.inject.Inject;

import com.ericsson.oss.itpf.sdk.context.ContextService;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;

public class ExternalCRLHelper {
    @Inject
    private ContextService ctxService;

    @Inject
    EServiceManager eServiceManager;

    public List<ExternalCRLInfo> listExternalCRLInfo(final String caName) {
        RBACManagement.injectUserName(ctxService);
        final List<ExternalCRLInfo> externalCRLInfos = eServiceManager.getPkiExtCACRLManager().listExternalCRLInfo(caName);
        return externalCRLInfos;
    }
}
