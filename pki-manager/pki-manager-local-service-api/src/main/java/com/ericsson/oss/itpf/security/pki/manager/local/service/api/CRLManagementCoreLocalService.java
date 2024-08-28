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
package com.ericsson.oss.itpf.security.pki.manager.local.service.api;



import javax.ejb.Local;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CACertificateIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLInfo;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.InvalidCoreEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.core.exception.revocation.CertificateRevokedException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateExpiredException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.*;

/**
 * This is an interface for CRLManagement. It provides a method which is used to create a new transaction if a request is not associated with any transaction.
 * 
 * @author xramdag
 *
 */
@EService
@Local
public interface CRLManagementCoreLocalService {

    /**
     * This method is used to generateCRL for a given CA and Certificate serial number.
     * 
     * @param caCertIdentifier
     *            CRLInfo is generated using Certificate identified by {@link CACertificateIdentifier} object.
     * @return CRLInfo is the {@link CRLInfo} object which contains the details about the generated CRL.
     * @throws CertificateNotFoundException
     *             in case the CA Certificate to issue CRL is not found.
     * @throws CertificateExpiredException
     * @throws CertificateRevokedException
     *             thrown when the CRL request is received for a revoked certificate.
     * @throws CoreEntityNotFoundException
     *             in case of {@link CertificateAuthority} does not exist.
     * @throws CRLGenerationException
     *             Thrown when internal error occurs during CRL generation.
     * @throws CRLGenerationInfoNotFoundException
     *             Thrown when CRLGeneration information is null or empty.
     * @throws CRLServiceException
     *             thrown in case of any database failures or internal errors.
     * @throws ExpiredCertificateException
     *             thrown when the CRL request is received for an expired certificate.
     * @throws InvalidCAException
     *             Thrown when the given CAEntity is not valid.
     * @throws InvalidCRLExtensionException
     *             thrown in case of CRL extensions passed in are not valid.
     * @throws InvalidCRLGenerationInfoException
     *             Thrown when CRLGeneration information is invalid.
     * @throws InvalidCoreEntityAttributeException
     *             Thrown when an invalid attribute is present in the entity.
     * @throws RevokedCertificateException
     *             thrown when the CRL request is received for a revoked certificate.
     */
    CRLInfo generateCrl(final CACertificateIdentifier caCertIdentifier) throws CertificateNotFoundException, CertificateExpiredException, CertificateRevokedException, CoreEntityNotFoundException,
            CRLGenerationException, CRLGenerationInfoNotFoundException, CRLServiceException, ExpiredCertificateException, InvalidCAException, InvalidCRLExtensionException,
            InvalidCRLGenerationInfoException, InvalidCoreEntityAttributeException, RevokedCertificateException;
}
