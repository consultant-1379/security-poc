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
package com.ericsson.itpf.security.pki.web.cli.local.service.ejb;

import javax.ejb.Stateless;
import javax.ejb.TransactionAttribute;
import javax.ejb.TransactionAttributeType;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.web.cli.local.service.api.CSRManagementService;
import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.CACertificateManagementService;

/**
 * Service Bean of CSRManagementServiceBean having the implementation of CSRManagementService.
 *
 */
@Stateless
public class CSRManagementServiceBean implements CSRManagementService {

    @EServiceRef
    CACertificateManagementService caCertificateManagementService;

    @Inject
    Logger logger;

    /**
     * This method will generate CSR.
     *
     * @param caEntityName
     *
     * @param newKey
     *
     * @return PKCS10CertificationRequestHolder
     */

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public PKCS10CertificationRequestHolder generateCSR(final String caEntityName, final boolean newKey) {

        return caCertificateManagementService.generateCSR(caEntityName, newKey);
    }

    /**
     * This method will get CSR.
     *
     * @param caEntityName
     *            name of caEntity
     *
     * @return PKCS10CertificationRequestHolder
     */

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public PKCS10CertificationRequestHolder getCSR(final String caEntityName) {
        return caCertificateManagementService.getCSR(caEntityName);
    }
}