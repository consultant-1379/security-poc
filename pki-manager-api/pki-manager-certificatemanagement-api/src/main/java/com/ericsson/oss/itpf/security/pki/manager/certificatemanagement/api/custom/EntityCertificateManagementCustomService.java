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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api.custom;

import javax.ejb.Remote;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.manager.exception.EntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.ProfileException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.CertificateException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.InvalidCertificateRequestException;
import com.ericsson.oss.itpf.security.pki.manager.model.certificate.custom.secgw.SecGWCertificates;

/**
 * This interface is for any customer specific operations for any customer specific requirements. Below are the operations provided
 * <ul>
 * <li>Issue/Ressiue certificate for Security gateway - specific requirement by AT&T</li>
 * </ul>
 */

@EService
@Remote
public interface EntityCertificateManagementCustomService {

    /**
     * This method is for generation of certificate for security gateway with PKCS10 Request and to get certificate, certificate chain and required trusted certificates for security gateway. Entity
     * name for certificate generation will be taken from CN of CSR, this Entity name will be used to create or update security gateway entity. If Entity with the entity name is not exist, new entity
     * will be created with values taken from CSR else it updates the existing entity.
     *
     * @param entityName
     *            name of the entity for which certificate needs to be generated.
     * @param certificateRequest
     *            {@link CertificateRequest} holder object containing PKCS10 request.
     * @param isChainRequired
     *            is chain required for certificate
     * @return SecGWCerificates contains certificate, certificateChain and trusted certificates.
     * @throws AlgorithmNotFoundException
     *             Thrown when the algorithm mapped to entity profile is not found.
     * @throws CertificateException
     *             Thrown when certificate generation failed
     * @throws EntityException
     *             Thrown when invalid data found in secgw entity creation or updation
     * @throws IllegalArgumentException
     *             Thrown if the given Certificate Request has unsupported fields.
     * @throws InvalidCertificateRequestException
     *             Thrown when given Certificate Request is invalid
     * @throws ProfileException
     *             Thrown when the Entity Profile or Trust Profile mapped to entity are invalid
     */
    SecGWCertificates generateSecGWCertificate(final String entityName, final CertificateRequest certificateRequest,
            final Boolean isChainRequired) throws AlgorithmNotFoundException, CertificateException, EntityException,
            IllegalArgumentException, InvalidCertificateRequestException, ProfileException;
}