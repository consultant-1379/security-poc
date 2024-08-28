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
package com.ericsson.itpf.security.pki.web.cli.local.service.api;

import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.manager.exception.InvalidOperationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.CertificateRequestGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;

/**
 * Local service for generating the CSR and getting the CSR
 */
@EService
@Local
public interface CSRManagementService {

    /**
     * This method will generate CSR.
     * 
     * @param caEntityName
     *            name of the {@link CAEntity}
     * @param newKey
     *            boolean which specifies whether new key to be generated or not.
     * @return PKCS10CertificationRequestHolder generated CSR
     */
    PKCS10CertificationRequestHolder generateCSR(final String caEntityName, final boolean newKey);

    /**
     * This method will get CSR.
     * 
     * @param caEntityName
     *            name of caEntity
     * @return PKCS10CertificationRequestHolder generated CSR
     * @throws CANotFoundException
     *             Thrown when given CAEntity doesn't exists.
     * @throws CertificateRequestGenerationException
     *             Thrown when CertificateRequest generation or export is failed.
     * @throws CertificateServiceException
     *             is thrown when internal db error occurs while fetching CSR.
     * @throws InvalidOperationException
     *             Thrown when the certificateGenerationInfo is not found.
     */
    PKCS10CertificationRequestHolder getCSR(final String caEntityName) throws CANotFoundException, CertificateRequestGenerationException, CertificateServiceException, InvalidOperationException;
}
