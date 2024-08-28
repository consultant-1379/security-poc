/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2017
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.itpf.security.pki.web.cli.local.service.ejb;

import java.util.List;

import javax.ejb.*;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.web.cli.local.service.api.CertificateManagementLocalService;
import com.ericsson.oss.itpf.sdk.core.annotation.EServiceRef;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.CACertificateManagementService;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;

/**
 * Service Bean of CertificateManagementLocalServiceBean having the implementation of CertificateManagementLocalService.
 * 
 */

@Stateless
public class CertificateManagementLocalServiceBean implements CertificateManagementLocalService {

    @EServiceRef
    CACertificateManagementService caCertificateManagementService;

    @Inject
    Logger logger;

    @Override
    @TransactionAttribute(TransactionAttributeType.REQUIRES_NEW)
    public List<Certificate> listCertificates(final String entityName, final CertificateStatus... certificateStatus) throws CertificateServiceException,
            EntityNotFoundException {
      return caCertificateManagementService.listCertificates_v1(entityName, certificateStatus);
    }
}
