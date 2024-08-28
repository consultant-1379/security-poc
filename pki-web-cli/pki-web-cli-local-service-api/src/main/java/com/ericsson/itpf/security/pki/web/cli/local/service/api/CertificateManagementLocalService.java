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
package com.ericsson.itpf.security.pki.web.cli.local.service.api;

import java.util.List;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;

/**
 * The interface is used as local service to provide List certificates functionality by taking the entity name and certificate status
 *
 * @author xkumkam
 *
 */
@EService
@Local
public interface CertificateManagementLocalService {

    List<Certificate> listCertificates(final String entityName, final CertificateStatus... certificateStatus) throws CertificateServiceException,
            EntityNotFoundException, RevokedCertificateException;
}
