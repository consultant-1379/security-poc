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
package com.ericsson.oss.itpf.security.pki.manager.common.modelmapperv1;

import java.util.List;

import com.ericsson.oss.itpf.security.pki.manager.exception.entity.CAEntityNotInternalException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.TrustProfileData;

/**
 * This interface contains basic methods that are to be implemented by model mappers Model Mappers does the following basic operation:
 * <ul>
 * <li>Convert from API Model to JPA Entity</li>
 * <li>Convert from JPA Entity to API Model</li>
 * </ul>
 *
 */
public interface ModelMapperv1 {
    /**
     * This method maps the JPA Entity to its corresponding API Model.
     *
     * @param dataModel
     *            Instance of {@link TrustProfileData}/ CertificateProfileData / {@link EntityProfileData}
     * @return Instance of {@link TrustProfile}/ {@link CertificateProfile} / {@link EntityProfile}
     *
     * @throws CAEntityNotInternalException
     *             Thrown when given CA Entity exists but it's an external CA.
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping Profiles
     */
    <T, E> T toApi(E dataModel, MappingDepth depth) throws CAEntityNotInternalException, InvalidEntityAttributeException,
    InvalidProfileAttributeException;

    /**
     * This method maps the API Model to its corresponding JPA Entity.
     *
     * @param aPIModel
     *            Instance of {@link TrustProfile}/ {@link CertificateProfile} / {@link EntityProfile}
     * @return Instance of {@link TrustProfileData}/ CertificateProfileData / {@link EntityProfileData}
     *
     * @throws EntityServiceException
     *             thrown when any internal Database errors occur.
     * @throws ProfileServiceException
     *             thrown when any internal Database errors occur.
     */
    <T, E> E fromApi(T aPIModel) throws EntityServiceException, ProfileServiceException;

    /**
     * This method maps the list of JPA Entities to its corresponding API Model list.
     *
     * @param depth
     *            the depth of modeled objects
     * @param dataModelList
     *            {@link java.util.List} of {@link CAEntity}/{@link Entity}
     *
     * @return {@link java.util.List} of {@link CAEntityData}/{@link EntityData}
     *
     * @throws CANotFoundException
     *             Thrown when CA is not found.
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping profile
     */
    <T, E> List<T> toApi(List<E> entityDatas, MappingDepth depth) throws CANotFoundException, InvalidEntityAttributeException,
    InvalidProfileAttributeException;

    /**
     * This method maps the list of JPA Entities to its corresponding API Model list.
     *
     * @param dataModelList
     *            {@link java.util.List} of {@link CAEntity}/{@link Entity}
     *
     * @return {@link java.util.List} of {@link CAEntityData}/{@link EntityData}
     *
     * @throws CANotFoundException
     *             Thrown when CA is not found.
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid Attribute is found while mapping profile
     */
    <T, E> List<T> toApiWithoutIssuerData(List<E> entityDatas)
            throws CANotFoundException, InvalidEntityAttributeException, InvalidProfileAttributeException;

    /**
     * This method Maps the Entity JPA model to its corresponding API model. This method maps the name, subject, status and certificate of the entity.
     *
     * @param entityData
     *            EntityData Object which should be converted to API model Entity
     *
     * @return Returns the API model of the given JPA model
     *
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     */
    <T> T getEntitySummaryWithCertificates(EntityData entityData) throws InvalidEntityAttributeException;
}
