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
package com.ericsson.oss.itpf.security.credmservice.ejb;

import java.util.ArrayList;
import java.util.List;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.credmservice.api.ExtCACRLManagementInterface;
import com.ericsson.oss.itpf.security.credmservice.impl.ExternalCRLHelper;
import com.ericsson.oss.itpf.security.pki.manager.exception.external.credentialmgmt.crl.ExternalCRLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.crl.ExternalCRLInfo;

@Stateless
public class ExtCACRLManagementBean implements ExtCACRLManagementInterface {

    @Inject
    ExternalCRLHelper certificateManager;

    private static final Logger log = LoggerFactory.getLogger(ExtCACRLManagementBean.class);

    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public List<ExternalCRLInfo> listExternalCRLInfo(final String caName) {
        List<ExternalCRLInfo> externalCRLInfos = new ArrayList<ExternalCRLInfo>();
        try {
        externalCRLInfos = certificateManager.listExternalCRLInfo(caName);
        
        } catch (ExternalCRLNotFoundException ex) {
            log.info("No CRL found for Ext CA " + caName);
        }
        return externalCRLInfos;
    }
}
