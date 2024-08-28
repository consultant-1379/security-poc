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
package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.validator;

import com.ericsson.oss.itpf.security.pki.manager.common.enums.OperationType;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.*;
//import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyExistsException;
//import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.*;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.*;

/**
 * This interface holds basic methods that are to be implemented by all profile/entity validators. It contains two methods:
 * <ul>
 * <li>Validate - which takes entity and operation type as input and redirects to other method based on opetaion type.</li>
 * <li>Availability of Name</li>
 * </ul>
 */
public interface BasicValidator {
    /**
     * This method validates the input entity i.e, {@link TrustProfile}/ {@link CertificateProfile} / {@link EntityProfile} / {@link CAEntity} / {@link Entity} based on {@link OperationType}
     * 
     * @param entity
     *            Instance of {@link TrustProfile}/ {@link CertificateProfile} / {@link EntityProfile} / {@link CAEntity} / {@link Entity}
     * @param operationType
     *            Type of Operation {@link OperationType}
     * @throws InternalServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws ProfileNotFoundException
     *             thrown when given EntityProfile inside CA Entity/Entity doesn't exist or in inactive state.
     * @throws EntityAlreadyExistsException
     *             thrown when trying to create an entity that already exists.
     * @throws EntityNotFoundException
     *             thrown when no entity exists with given id/name and entity profile name.
     * @throws UnsupportedCRLVersionException
     *             thrown if the given CRL version is not supported.
     * @throws CRLExtensionException
     *             thrown if the the CRL extensions are invalid.
     * @throws InvalidCRLGenerationInfoException
     *             thrown if the CRLGenerationInfo Fields are invalid.
     */
    <T> void validate(T entity, OperationType operationType) throws AlgorithmNotFoundException, CANotFoundException, CertificateExtensionException, EntityCategoryNotFoundException,
            InvalidCAException, InvalidEntityCategoryException, InvalidProfileAttributeException, InvalidSubjectException, MissingMandatoryFieldException, ProfileAlreadyExistsException,
            ProfileNotFoundException, ProfileServiceException, UnSupportedCertificateVersion, UnsupportedCRLVersionException, CRLExtensionException, InvalidCRLGenerationInfoException;

    /**
     * Check whether given name is valid or not ofr a given Profile Class {@link TrustProfile}/ {@link CertificateProfile} / {@link EntityProfile} / {@link CAEntity} / {@link Entity}
     * 
     * @param name
     *            name to be checked
     * @param entity
     *            Class of {@link TrustProfile}/ {@link CertificateProfile} / {@link EntityProfile} / {@link CAEntity} / {@link Entity}
     * @return <code>true</code> or <code>false</code>
     * 
     * @throws InternalServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    <T> boolean isNameAvailable(String name, Class<T> entity) throws ProfileServiceException;

}
