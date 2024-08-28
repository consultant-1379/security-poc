/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.core.entitymanagement.api;

import java.util.List;

import javax.ejb.Remote;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.core.exception.crlmanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateException;

/**
 * This is an interface for CA Entity management service and provides API's for below operations.
 * <ul>
 * <li>Creation of CA Entities</li>
 * <li>Update of CA Entities</li>
 * <li>Deletion of CA Entities</li>
 * </ul>
 *
 * @author xrajaba
 * @since 21/07/15
 */

@EService
@Remote
public interface CAEntityManagementService {

    /**
     * Creates {@link CertificateAuthority} object.
     *
     * @param certificateAuthority
     *            certificateAuthority object to be created.
     * @return CertificateAuthority certificateAuthority updated object
     * @throws CoreEntityAlreadyExistsException
     *             Thrown when creating {@#link CertificateAuthority} object that already exists.
     * @throws CoreEntityServiceException
     *             Thrown when any internal Database errors or service exception occur.
     * @throws InvalidCoreEntityAttributeException
     *             Thrown when an invalid attribute is present in the CAEntity.
     */
    CertificateAuthority createCA(CertificateAuthority certificateAuthority) throws CoreEntityAlreadyExistsException, CoreEntityServiceException, InvalidCoreEntityAttributeException;

    /**
     * Updates {@link CertificateAuthority} object.
     *
     * @param certificateAuthority
     *            certificateAuthority object to be updated in the database.
     * @return CertificateAuthority certificateAuthority updated object
     * @throws CoreEntityAlreadyExistsException
     *             Thrown in case when updating with name that already exists.
     * @throws CoreEntityNotFoundException
     *             Thrown when updating {@link CertificateAuthority} object that does not exist.
     * @throws CoreEntityServiceException
     *             Thrown when any internal Database errors or service exception occur.
     * @throws InvalidCoreEntityAttributeException
     *             Thrown when an invalid attribute is present in the CAEntity.
     */
    CertificateAuthority updateCA(CertificateAuthority certificateAuthority) throws CoreEntityAlreadyExistsException, CoreEntityNotFoundException, CoreEntityServiceException,
            InvalidCoreEntityAttributeException;

    /**
     * Deletes {@link CertificateAuthority} object.
     *
     * @param certificateAuthority
     *            certificateAuthroity object to be deleted.
     * @throws CoreEntityInUseException
     *             Thrown in case when {@link CertificateAuthority} has active certificate.
     * @throws CoreEntityNotFoundException
     *             Thrown in case when deleting {@link CertificateAuthority} object that does not exist.
     * @throws CoreEntityServiceException
     *             Thrown when any internal Database errors or service exception occur.
     *
     */
    void deleteCA(CertificateAuthority certificateAuthority) throws CoreEntityInUseException, CoreEntityNotFoundException, CoreEntityServiceException;

    /**
     * This method is used to import CertificateAuthority
     *
     * @param certificateAuthorityList
     *            List certificateAuthority object to be created.
     * @return certificateAuthorityList List of certificateAuthority objects created.
     * @throws CoreEntityAlreadyExistsException
     *             Thrown when creating {@#link CertificateAuthority} object that already exists.
     * @throws CoreEntityServiceException
     *             Thrown when any internal Database errors occur.
     *
     */
    List<CertificateAuthority> importCAEntities(List<CertificateAuthority> certificateAuthorityList) throws CoreEntityAlreadyExistsException, CoreEntityServiceException;

}
