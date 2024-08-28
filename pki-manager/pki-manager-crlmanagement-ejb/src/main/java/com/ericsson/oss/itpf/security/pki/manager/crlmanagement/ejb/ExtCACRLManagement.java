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
package com.ericsson.oss.itpf.security.pki.manager.crlmanagement.ejb;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.inject.Inject;

import com.ericsson.oss.itpf.security.pki.manager.crlmanagement.impl.ExtCACRLManager;

@Stateless
public class ExtCACRLManagement {
    @Inject
    ExtCACRLManager extCACRLManager;

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public void autoUpdateExpiredCRLs() {
        extCACRLManager.autoUpdateExpiredCRLs();
    }

}
