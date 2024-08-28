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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.api;

import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;

/**
 * Interface for common Certificate Management operations for CAEntity and Entity. Provides below operation
 * <ul>
 * <li>List certificates based on Certificate status</li>
 * </ul>
 * 
 */
public interface CertificateManagementService {

    /**
     * Returns a list of certificates issued for the CAEntity or Entity based on CertificateStatus
     * 
     * @param entityName
     *            name of the CAEntity or Entity
     * @param status
     *            The list of {@link CertificateStatus} values for which Certificates have to be listed
     * 
     * @return list of certificates of for the given CAEntity or entity based on status. In each certificate object, only the following fields are filled for issuer attribute in CertificateAuthority.
     *         <ul>
     *         <li>protected long id</li>
     *         <li>protected String name</li>
     *         <li>protected boolean isRootCA</li>
     *         <li>protected Subject subject</li>
     *         <li>protected SubjectAltName subjectAltName</li>
     *         <li>protected CAStatus status</li>
     *         <li>protected boolean publishToCDPS</li>
     *         </ul>
     * 
     * @throws CertificateNotFoundException
     *             Thrown if certificate not found for the given entity with corresponding status.
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws EntityNotFoundException
     *             Thrown when given Entity/CAEntity doesn't exists.
     * @throws InvalidEntityAttributeException
     *             Throws in case of the given entity has invalid attribute.
     */
    @Deprecated
    List<Certificate> listCertificates(final String entityName, final CertificateStatus... status) throws CertificateNotFoundException, CertificateServiceException, EntityNotFoundException,
            InvalidEntityAttributeException;

    /**
     * Returns a list of certificates issued for the CAEntity or Entity based on CertificateStatus
     * 
     * @param entityName
     *            name of the CAEntity or Entity
     * @param status
     *            The list of {@link CertificateStatus} values for which Certificates have to be listed
     * 
     * @return list of certificates of for the given CAEntity or entity based on status. In each certificate object, only the following fields are filled for issuer attribute in CertificateAuthority.
     *         <ul>
     *         <li>protected long id</li>
     *         <li>protected String name</li>
     *         <li>protected boolean isRootCA</li>
     *         <li>protected Subject subject</li>
     *         <li>protected SubjectAltName subjectAltName</li>
     *         <li>protected CAStatus status</li>
     *         <li>protected boolean publishToCDPS</li>
     *         </ul>
     * 
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws EntityNotFoundException
     *             Thrown when given Entity/CAEntity doesn't exists.
     * @throws InvalidEntityAttributeException
     *             Throws in case of the given entity has invalid attribute.
     */
    List<Certificate> listCertificates_v1(final String entityName, final CertificateStatus... status) throws CertificateServiceException, EntityNotFoundException, InvalidEntityAttributeException;
}
