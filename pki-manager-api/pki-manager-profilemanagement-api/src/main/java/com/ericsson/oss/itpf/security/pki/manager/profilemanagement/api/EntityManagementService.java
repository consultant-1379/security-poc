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

package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api;

import java.util.List;

import javax.ejb.Remote;

import com.ericsson.oss.itpf.sdk.core.annotation.EService;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.enrollment.EnrollmentURLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.OTPException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.exception.trustdistributionpoint.TrustDistributionPointURLNotDefinedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.trustdistributionpoint.TrustDistributionPointURLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.model.*;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.*;

/**
 * This is an interface for entity management service and provides API's for below operations.
 * <ul>
 * <li>Importing entities in bulk manner.</li>
 * <li>CRUD of entities</li>
 * </ul>
 */
@EService
@Remote
public interface EntityManagementService {
    /**
     * Import all entities in bulk manner.
     * 
     * @param entities
     *            Entities object containing Entities/CAEntities.
     * 
     * @throws AlgorithmNotFoundException
     *             thrown when given key generation algorithm is not found or inactive.
     * @throws CRLExtensionException
     *             thrown if the the CRL extensions are invalid.
     * @throws EntityAlreadyExistsException
     *             thrown when Entity or CAEntity already exists.
     * @throws EntityCategoryNotFoundException
     *             thrown when category doesn't exists with the given name.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidCRLGenerationInfoException
     *             thrown if the CRLGenerationInfo Fields are invalid.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when given given attributes of Entity or CAEntity have invalid value.
     * @throws InvalidEntityCategoryException
     *             thrown when the given category is in invalid format.
     * @throws InvalidProfileException
     *             thrown when invalid profile is mapped to Entity or CAEntity
     * @throws InvalidSubjectAltNameExtension
     *             thrown when invalid subject alternative name is given
     * @throws InvalidSubjectException
     *             thrown when invalid subject is given
     * @throws MissingMandatoryFieldException
     *             thrown when any mandatory fields are not given
     * @throws OTPException
     *             thrown when any OTP details validation fails
     * @throws ProfileNotFoundException
     *             thrown if given entity contains the entity profile that doesn't exists.
     * @throws UnsupportedCRLVersionException
     *             thrown if the given CRL version is not supported.
     */
    void importEntities(Entities entities) throws AlgorithmNotFoundException, CRLExtensionException, EntityAlreadyExistsException, EntityCategoryNotFoundException, EntityServiceException,
            InvalidCRLGenerationInfoException, InvalidEntityException, InvalidEntityAttributeException, InvalidEntityCategoryException, InvalidProfileException, InvalidSubjectAltNameExtension,
            InvalidSubjectException, MissingMandatoryFieldException, OTPException, ProfileNotFoundException, UnsupportedCRLVersionException;

    /**
     * Update entities in bulk manner.
     *
     * @param entities
     *            Entities object containing Entites/CAEntities to be updated.
     *
     * @throws AlgorithmNotFoundException
     *             thrown when given key generation algorithm is not found or inactive.
     * @throws CRLExtensionException
     *             thrown if the the CRL extensions are invalid.
     * @throws CRLGenerationException
     *             thrown when any exception occurred during CRLGeneration.
     * @throws EntityAlreadyExistsException
     *             thrown when given updated name in Entity or CAEntity already exists.
     * @throws EntityCategoryNotFoundException
     *             thrown when category doesn't exists with the given name.
     * @throws EntityNotFoundException
     *             thrown when given Entity or CAEntity is not found.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidCRLGenerationInfoException
     *             thrown if the CRLGenerationInfo Fields are invalid.
     * @throws InvalidEntityException
     *             thrown if the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when given updated attributes of Entity or CAEntity have invalid value.
     * @throws InvalidEntityCategoryException
     *             thrown when the given category is in invalid format.
     * @throws InvalidProfileException
     *             thrown when invalid profile is mapped to Entity or CAEntity
     * @throws InvalidSubjectAltNameExtension
     *             thrown when invalid subject alternative name is given
     * @throws InvalidSubjectException
     *             thrown when invalid subject is given
     * @throws MissingMandatoryFieldException
     *             thrown when any mandatory fields are not given
     * @throws OTPException
     *             thrown when any OTP details validation fails
     * @throws ProfileNotFoundException
     *             thrown if given entity contains the entity profile that doesn't exists.
     * @throws UnsupportedCRLVersionException
     *             thrown if the given CRL version is not supported.
     */
    void updateEntities(Entities entities) throws AlgorithmNotFoundException, CRLExtensionException, CRLGenerationException, EntityAlreadyExistsException, EntityCategoryNotFoundException,
            EntityNotFoundException, EntityServiceException, InvalidCRLGenerationInfoException, InvalidEntityException, InvalidEntityAttributeException, InvalidEntityCategoryException,
            InvalidProfileException, InvalidSubjectAltNameExtension, InvalidSubjectException, MissingMandatoryFieldException, OTPException, ProfileNotFoundException, UnsupportedCRLVersionException;

    /**
     * Bulk deletion of entities of any type based on id or name.To delete any entity, id/name should be set in the list of Entity/CAEntity objects and sent as Entities.
     *
     * @param entities
     *            Contains list of Entity,CAEntity objects with id/name filled.
     * @throws EntityInUseException
     *             thrown when given entity to be deleted is in use by other profiles.
     * @throws EntityNotFoundException
     *             thrown when no entity exists with given id/name.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityAttributeException
     *             thrown when given entity has invalid attribute.
     *
     */
    void deleteEntities(Entities entities) throws EntityInUseException, EntityNotFoundException, EntityServiceException, InvalidEntityAttributeException;

    /**
     * Create a CAEntity/Entity.
     *
     * @param entity
     *            Object of CAEntity/Entity.
     * @return return created entity object.
     *
     * @throws AlgorithmNotFoundException
     *             thrown when given key generation algorithm is not found or inactive.
     * @throws CRLExtensionException
     *             thrown if the the CRL extensions are invalid.
     * @throws CRLGenerationException
     *             thrown when any exception occurred during CRLGeneration.
     * @throws EntityAlreadyExistsException
     *             thrown when Entity or CAEntity already exists.
     * @throws EntityCategoryNotFoundException
     *             thrown when category doesn't exists with the given name.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidCRLGenerationInfoException
     *             thrown if the CRLGenerationInfo Fields are invalid.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when given given attributes of Entity or CAEntity have invalid value.
     * @throws InvalidEntityCategoryException
     *             thrown when the given category is in invalid format.
     * @throws InvalidProfileException
     *             thrown when invalid profile is mapped to Entity or CAEntity
     * @throws InvalidSubjectAltNameExtension
     *             thrown when invalid subject alternative name is given
     * @throws InvalidSubjectException
     *             thrown when invalid subject is given
     * @throws MissingMandatoryFieldException
     *             thrown when any mandatory fields are not given
     * @throws ProfileNotFoundException
     *             thrown if given entity contains the entity profile that doesn't exists.
     * @throws UnsupportedCRLVersionException
     *             thrown if the given CRL version is not supported.
     */
    @Deprecated
    <T extends AbstractEntity> T createEntity(T entity) throws AlgorithmNotFoundException, CRLExtensionException, CRLGenerationException, EntityAlreadyExistsException, EntityServiceException,
            EntityCategoryNotFoundException, InvalidCRLGenerationInfoException, InvalidEntityException, InvalidEntityAttributeException, InvalidEntityCategoryException, InvalidProfileException,
            InvalidSubjectAltNameExtension, InvalidSubjectException, MissingMandatoryFieldException, ProfileNotFoundException, UnsupportedCRLVersionException;

    /**
     * Create a CA Entity or Entity.
     * 
     * @param entity
     *            Object of CAEntity/Entity.
     * @return return created entity object.
     * 
     * @throws AlgorithmNotFoundException
     *             thrown when given key generation algorithm is not found or inactive.
     * @throws CRLExtensionException
     *             thrown if the the CRL extensions are invalid.
     * @throws EntityAlreadyExistsException
     *             thrown when Entity or CAEntity already exists.
     * @throws EntityCategoryNotFoundException
     *             thrown when category doesn't exists with the given name.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidCRLGenerationInfoException
     *             thrown if the CRLGenerationInfo Fields are invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when given given attributes of Entity or CAEntity have invalid value.
     * @throws InvalidEntityCategoryException
     *             thrown when the given category is in invalid format.
     * @throws InvalidProfileException
     *             thrown when invalid profile is mapped to Entity or CAEntity
     * @throws InvalidSubjectAltNameExtension
     *             thrown when invalid subject alternative name is given
     * @throws InvalidSubjectException
     *             thrown when invalid subject is given
     * @throws MissingMandatoryFieldException
     *             thrown when any mandatory fields are not given
     * @throws OTPException
     *             thrown when any OTP details validation fails
     * @throws ProfileNotFoundException
     *             thrown if given entity contains the entity profile that doesn't exists.
     * @throws UnsupportedCRLVersionException
     *             thrown if the given CRL version is not supported.
     */
    @java.lang.SuppressWarnings("squid:S00100")
    <T extends AbstractEntity> T createEntity_v1(T entity) throws AlgorithmNotFoundException, CRLExtensionException, CRLGenerationException, EntityAlreadyExistsException, EntityServiceException,
            EntityCategoryNotFoundException, InvalidCRLGenerationInfoException, InvalidEntityException, InvalidEntityAttributeException, InvalidEntityCategoryException, InvalidProfileException,
            InvalidSubjectAltNameExtension, InvalidSubjectException, MissingMandatoryFieldException, OTPException, ProfileNotFoundException, UnsupportedCRLVersionException;

    /**
     * Update a CAEntity/Entity.
     *
     * @param entity
     *            Object of CAEntity/Entity with values to be updated.
     * @return Returns updated object of CAEntity/Entity.
     *
     * @throws AlgorithmNotFoundException
     *             thrown when given key generation algorithm is not found or inactive.
     * @throws CRLExtensionException
     *             thrown if the the CRL extensions are invalid.
     * @throws CRLGenerationException
     *             thrown when any exception occurred during CRLGeneration.
     * @throws EntityAlreadyExistsException
     *             thrown when given updated name in Entity or CAEntity already exists.
     * @throws EntityCategoryNotFoundException
     *             thrown when category doesn't exists with the given name.
     * @throws EntityNotFoundException
     *             thrown when given Entity or CAEntity is not found.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidCRLGenerationInfoException
     *             thrown if the CRLGenerationInfo Fields are invalid.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when given updated attributes of Entity or CAEntity have invalid value.
     * @throws InvalidEntityCategoryException
     *             thrown when the given category is in invalid format.
     * @throws InvalidProfileException
     *             thrown when invalid profile is mapped to Entity or CAEntity
     * @throws InvalidSubjectAltNameExtension
     *             thrown when invalid subject alternative name is given
     * @throws InvalidSubjectException
     *             thrown when invalid subject is given
     * @throws MissingMandatoryFieldException
     *             thrown when any mandatory fields are not given
     * @throws ProfileNotFoundException
     *             thrown if given entity contains the entity profile that doesn't exists.
     * @throws UnsupportedCRLVersionException
     *             thrown if the given CRL version is not supported.
     */
    @Deprecated
    <T extends AbstractEntity> T updateEntity(T entity) throws AlgorithmNotFoundException, CRLExtensionException, CRLGenerationException, EntityAlreadyExistsException,
            EntityCategoryNotFoundException, EntityNotFoundException, EntityServiceException, InvalidCRLGenerationInfoException, InvalidEntityException, InvalidEntityAttributeException,
            InvalidEntityCategoryException, InvalidProfileException, InvalidSubjectAltNameExtension, InvalidSubjectException, MissingMandatoryFieldException, ProfileNotFoundException,
            UnsupportedCRLVersionException;

    /**
     * Update a CA Entity or Entity.
     * 
     * @param entity
     *            Object of CAEntity/Entity with values to be updated.
     * @return Returns updated object of CAEntity/Entity.
     * 
     * @throws AlgorithmNotFoundException
     *             thrown when given key generation algorithm is not found or inactive.
     * @throws CRLExtensionException
     *             thrown if the the CRL extensions are invalid.
     * @throws EntityAlreadyExistsException
     *             thrown when given updated name in Entity or CAEntity already exists.
     * @throws EntityCategoryNotFoundException
     *             thrown when category doesn't exists with the given name.
     * @throws EntityNotFoundException
     *             thrown when given Entity or CAEntity is not found.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidCRLGenerationInfoException
     *             thrown if the CRLGenerationInfo Fields are invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when given updated attributes of Entity or CAEntity have invalid value.
     * @throws InvalidEntityCategoryException
     *             thrown when the given category is in invalid format.
     * @throws InvalidProfileException
     *             thrown when invalid profile is mapped to Entity or CAEntity
     * @throws InvalidSubjectAltNameExtension
     *             thrown when invalid subject alternative name is given
     * @throws InvalidSubjectException
     *             thrown when invalid subject is given
     * @throws MissingMandatoryFieldException
     *             thrown when any mandatory fields are not given
     * @throws OTPException
     *             thrown when any OTP details validation fails
     * @throws ProfileNotFoundException
     *             thrown if given entity contains the entity profile that doesn't exists.
     * @throws UnsupportedCRLVersionException
     *             thrown if the given CRL version is not supported.
     */
    @java.lang.SuppressWarnings("squid:S00100")
    <T extends AbstractEntity> T updateEntity_v1(T entity) throws AlgorithmNotFoundException, CRLExtensionException, CRLGenerationException, EntityAlreadyExistsException,
            EntityCategoryNotFoundException, EntityNotFoundException, EntityServiceException, InvalidCRLGenerationInfoException, InvalidEntityException, InvalidEntityAttributeException,
            InvalidEntityCategoryException, InvalidProfileException, InvalidSubjectAltNameExtension, InvalidSubjectException, MissingMandatoryFieldException, OTPException, ProfileNotFoundException,
            UnsupportedCRLVersionException;

    /** 
     * @deprecated
     * Get an Entity based on category (deprecated as this method makes credm list crashing on big databases)
     *
     * @param EntityCategory
     *            EntityCategory
     * @return Returns list of entities based on the value sent in EntityCategory object.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws EntityCategoryNotFoundException
     *             thrown when category doesn't exists with the given name.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the given entity is other than caentity/entiy.
     * @throws InvalidEntityAttributeException
     *             thrown when given Entity has invalid value
     * @throws InvalidEntityCategoryException
     *             thrown when the given entityCategory is Invalid.
     */
    @Deprecated
    List<Entity> getEntitiesByCategory(EntityCategory entityCategory)
            throws EntityCategoryNotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException,
            InvalidEntityCategoryException;

    /**
     * Get an Entity based on category.
     *
     * @param EntityCategory
     *            EntityCategory
     * @return Returns list of entities based on the value sent in EntityCategory object.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws EntityCategoryNotFoundException
     *             thrown when category doesn't exists with the given name.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the given entity is other than caentity/entiy.
     * @throws InvalidEntityAttributeException
     *             thrown when given Entity has invalid value
     * @throws InvalidEntityCategoryException
     *             thrown when the given entityCategory is Invalid.
     */
    List<Entity> getEntitiesByCategoryv1(EntityCategory entityCategory)
            throws EntityCategoryNotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException,
            InvalidEntityCategoryException;

    /**
     * Get an Entity Summary based on category.
     *
     * @param EntityCategory
     *            EntityCategory
     * @return Returns list of entities based on the value sent in EntityCategory object.
     *                 name, status and subject are the only field filled in the returned entities
     * @throws EntityCategoryNotFoundException
     *             thrown when category doesn't exists with the given name.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the given entity is other than caentity/entiy.
     * @throws InvalidEntityAttributeException
     *             thrown when given Entity has invalid value
     * @throws InvalidEntityCategoryException
     *             thrown when the given entityCategory is Invalid.
     */
    List<Entity> getEntitiesSummaryByCategory(EntityCategory entityCategory) throws EntityCategoryNotFoundException, EntityServiceException,
            InvalidEntityException, InvalidEntityAttributeException, InvalidEntityCategoryException;

    /**
     * Get an Entity based on Entity Id/name and entity profile name.
     *
     * @param entity
     *            Object of CAEntity with id/name set or Object of Entity with id/name and entity profile name set.
     * @return Returns object of CAEntity/Entity, where only the following fields are filled for issuer attribute in CAEntity(CertificateAuthority)/Entity(EntityInfo) objects.
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
     * @throws EntityNotFoundException
     *             thrown when no entity exists with given id/name.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when given entity has invalid attribute.
     */
    <T extends AbstractEntity> T getEntity(T entity) throws EntityNotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException;

    /**
     * Get an Entity used for import/update entity operation based on Entity Id/name and entity profile name.
     *
     * @param entity
     *            Object of CAEntity with id/name set or Object of Entity with id/name and entity profile name set.
     * @return Returns object of CAEntity/Entity, where only the following fields are filled for issuer attribute in
     *         CAEntity(CertificateAuthority)/Entity(EntityInfo) objects.
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
     * @throws EntityNotFoundException
     *             thrown when no entity exists with given id/name.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when given entity has invalid attribute.
     */
    <T extends AbstractEntity> T getEntityForImport(T entity) throws EntityNotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException;

    /**
     * Delete an CAEntity/Entity based on Id/name.
     *
     *
     * @param entity
     *            Object of CAEntity/Entity with id/name set.
     *
     * @throws EntityAlreadyDeletedException
     *             thrown when given entity is already deleted.
     * @throws EntityInUseException
     *             thrown when given entity to be deleted is in use by any other profile.
     * @throws EntityNotFoundException
     *             thrown when no entity exists with given id/name and entity profile name.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when given entity has invalid attribute.
     */
    <T extends AbstractEntity> void deleteEntity(T entity) throws EntityAlreadyDeletedException, EntityInUseException, EntityNotFoundException, EntityServiceException, InvalidEntityException,
            InvalidEntityAttributeException;

    /**
     * Get all entities based on type of class specified.
     *
     * @param EntityType
     *            Type of entity (CAEntity/Entity).
     * @return PKIEntities Object containing list of CAEntity/Entity objects.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when given entity has invalid attribute.
     */
    Entities getEntities(EntityType... entityType) throws EntityServiceException, InvalidEntityException, InvalidEntityAttributeException;

    /**
     * Get all entities used for import profiles operation based on type of class specified.
     *
     * @param EntityType
     *            Type of entity (CAEntity/Entity).
     * @return PKIEntities Object containing list of CAEntity/Entity objects.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when given entity has invalid attribute.
     */
    Entities getEntitiesForImport(EntityType... entityType) throws EntityServiceException, InvalidEntityException, InvalidEntityAttributeException;

    /**
     * Get CA/EndEntities by subject specified.
     *
     * @param EntityType
     *            Type of entity (CAEntity/Entity)
     * @param subject
     *            Object of subject class with fields set.
     * @return List of CA/EndEntities objects.
     *
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidSubjectException
     *             thrown when invalid subject is given.
     */
    @java.lang.SuppressWarnings("squid:S01452")
    List<? extends AbstractEntity> getEntitiesBySubject(Subject subject, EntityType entityType) throws EntityServiceException, InvalidSubjectException;

    /**
     * Check CAEntity/EndEntity name availability.
     *
     * @param name
     *            Name to be verified for the availability.
     * @param EntityType
     *            Class of entity to be checked (CAEntity/Entity).
     * @return true if name is available or else false.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when EntityType is other than caentity/entity.
     */
    boolean isEntityNameAvailable(String name, EntityType entityType) throws EntityServiceException, InvalidEntityException;

    /**
     * Used to get Enrollment info in case of SCEP and CMPV2.
     *
     * @param enrollmentType
     *            Type of enrollment.
     * @param entity
     *            Object of entity with required fields filled.
     * @return EnrollementInfo object containing the challenge password and other info required.
     *
     * @throws EntityNotFoundException
     *             thrown when given entity doesn't exists.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws EnrollmentURLNotFoundException
     *             thrown when loadBalancerAddress is not retrieved from the model
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws OTPExpiredException
     *             thrown when OTP count has reached 0 to inform CREDM that the existing OTP is no longer valid
     * @throws TrustDistributionPointURLNotFoundException
     *             thrown when TrustDistributionURL is not retrieved from TDPS.
     */
    EnrollmentInfo getEnrollmentInfo(EnrollmentType enrollmentType, Entity entity) throws EntityNotFoundException, EntityServiceException, EnrollmentURLNotFoundException, InvalidEntityException,
            InvalidEntityAttributeException, OTPExpiredException, TrustDistributionPointURLNotFoundException;

    /**
     * This method is used in case of SCEP for validating OTP
     *
     * @param entityName
     *            Name of the entity for which otp to be validated.
     * @param otp
     *
     * @return true/false
     * @throws EntityNotFoundException
     *             thrown when given entity doesn't exists.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws OTPExpiredException
     *             thrown when OTP count has reached 0 to inform CREDM that the existing OTP is no longer valid
     */
    boolean isOTPValid(String entityName, String otp) throws EntityNotFoundException, EntityServiceException, OTPExpiredException;

    /**
     * This method is used to update OTP and OTP Count for an Entity.
     *
     * @param entityName
     *            Name of the entity for which otp to be validated.
     * @param otp
     *            updated OTP value
     * @param otpCount
     *            updated OTP Count
     * @throws EntityNotFoundException
     *             thrown when given entity doesn't exists.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidOTPCountException
     *             thrown when OTP count exceeds 5 or is negative.
     * @throws InvalidOTPException
     *             when OTP passed is null.
     */
    @Deprecated
    void updateOTP(String entityName, String oTP, int oTPCount) throws EntityNotFoundException, EntityServiceException, InvalidOTPCountException, InvalidOTPException;

    /**
     * This method is used to update OTP, OTP Count and OTP Validity Period.
     * 
     * @param entityName
     *            Name of the entity for which OTP to be validated.
     * @param otp
     *            updated OTP value
     * @param otpCount
     *            updated OTP Count
     * @param otpValidityPeriod
     *            Time period in minutes after which OTP expires
     * @throws EntityNotFoundException
     *             thrown when given entity doesn't exists.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidOTPCountException
     *             thrown when OTP count exceeds 5 or is negative.
     * @throws InvalidOTPException
     *             when OTP passed is null.
     * @throws InvalidOtpValidityPeriodException
     *             thrown if the OTPValidityPeriod Field is invalid.
     */
    void updateOTP(String entityName, String otp, int otpCount, int otpValidityPeriod) throws EntityNotFoundException, EntityServiceException, InvalidOTPCountException, InvalidOTPException,
            InvalidOtpValidityPeriodException;

    /**
     * This method is used to get OTP for an Entity.
     *
     * @param entityName
     *            Name of the entity for which otp to be retrieved.
     * @throws EntityNotFoundException
     *             thrown when given entity doesn't exists.
     * @throws EntityServiceException
     *             thrown when any internal Database errors while retrieving entity by name. occur.
     * @throws OTPExpiredException
     *             Thrown when OTP count is 0 . OTP count is decreased everytime this method is called.
     * @throws OTPNotSetException
     *             Thrown when OTP is null.
     */
    String getOTP(String entityName) throws EntityNotFoundException, EntityServiceException, OTPExpiredException, OTPNotSetException;

    /**
     * This method is used to return TrustDistributionPointService URL for the given entity.
     *
     * @param entity
     *            Entity for which TrustDistribution URL has to be retrieved.
     * @param issuerName
     *            IssuerName of the entity for which URL has to be retrieved
     * @param certificateStatus
     *            Certificate status which could be either ACTIVE or INACTIVE.
     * @return TrustDistributionPointService URL.
     * @throws EntityNotFoundException
     *             thrown when given Entity or CAEntity is not found.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws TrustDistributionPointURLNotDefinedException
     *             thrown when TrustDistribution Publish Flag is not set.
     * @throws TrustDistributionPointURLNotFoundException
     *             thrown when TrustDistributionURL is not retrieved from TrustDistributionPointService.
     */
    <T extends AbstractEntity> String getTrustDistributionPointUrl(final T entity, final String issuerName, final CertificateStatus certificateStatus) throws EntityNotFoundException,
            EntityServiceException, TrustDistributionPointURLNotDefinedException, TrustDistributionPointURLNotFoundException;

    /**
     * This method is used to return TDPSUrlInfo object which contains both IPv4 and IPv6 TDPS urls for the Certificate which is identified by the given entity, issuerName and certificateStatus.
     *
     * @param entity
     *            Entity for which TrustDistribution IPV4 and IPV6 URLs have to be returned.
     * @param issuerName
     *            IssuerName of the entity certificate for which TrustDistribution IPV4 and IPV6 URLs have to be returned.
     * @param certificateStatus
     *            Certificate status which could be either ACTIVE or INACTIVE.
     * @return TDPSUrlInfo object it contains IPv4 and IPv6 TrustDistributionPointService urls.
     * @throws EntityNotFoundException
     *             thrown when given Entity or CAEntity is not found.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws TrustDistributionPointURLNotDefinedException
     *             thrown when TrustDistribution Publish Flag is not set.
     * @throws TrustDistributionPointURLNotFoundException
     *             thrown when TrustDistributionURL is not retrieved for the certificate which is identified by the given entity, issuer name and certificate status.
     */
    <T extends AbstractEntity> TDPSUrlInfo getTrustDistributionPointUrls(final T entity, final String issuerName, final CertificateStatus certificateStatus) throws EntityNotFoundException,
            EntityServiceException, TrustDistributionPointURLNotDefinedException, TrustDistributionPointURLNotFoundException;

    /**
     * Returns EntityName of the Certificates signed by the issuer and certificates serialnumber
     *
     * @param issuerName
     *            Name of the Certificate Issuer
     * @param serialNumber
     *            SerialNumber of the issued certificate by Issuer
     * @return EntityName name of the Entity
     * @throws CANotFoundException
     *             Thrown in case the given CAEntity does not signed any certificate.
     * @throws InvalidEntityException
     *             thrown when the EntityType is other than caentity/entity.
     * @throws SerialNumberNotFoundException
     *             Thrown in case there is no certificate with signed by CA with that SerialNumber
     */
    String getEntityNameByIssuerNameAndSerialNumber(final String issuerName, final String serialNumber) throws CANotFoundException, InvalidEntityException, SerialNumberNotFoundException;

    /**
     * Returns List of EntityName(s) of the Certificates signed by the issuer.
     *
     * @param issuerName
     *            Name of the Certificate Issuer
     * @return List of EntityName ` List of the name(s) of the Entity
     * @throws InvalidEntityException
     *             thrown when the EntityType is other than caentity/entity.
     * @throws CANotFoundException
     *             Thrown in case the given CAEntity does not signed any certificate.
     */
    List<String> getEntityNameListByIssuerName(String issuerName) throws CANotFoundException, InvalidEntityException;

    /**
     * Returns List of EntityName(s) which are mapped to a trustprofile.
     *
     * @param trustProfileName
     *            Name of the TrustProfile
     * @return List of EntityName List of the name(s) of the Entity
     * @throws InvalidEntityException
     *             thrown when the entity is invalid.
     * @throws ProfileNotFoundException
     *             Thrown in case the provided Profile does not exist.
     */
    List<String> getEntityNameListByTrustProfileName(String trustProfileName) throws InvalidEntityException, ProfileNotFoundException;

    /**
     * Returns List of Entity(s) of the Certificates signed by the issuer.
     *
     * @param issuerName
     *            Name of the Certificate Issuer
     * @return List of Entity List of the Entity
     * @throws CANotFoundException
     *             Thrown in case the given CAEntity does not signed any certificate.
     * @throws InvalidEntityException
     *             thrown when the EntityType is other than caentity/entity.
     */
    List<Entity> getEntityListByIssuerName(String issuerName) throws CANotFoundException, InvalidEntityException;

    /**
     * This method returns CA Hierarchies for each root CA
     *
     * @return List of {@link TreeNode} object containing CA Hierarchies in tree format.
     *
     * @throws EntityNotFoundException
     *             Throws when RootCA is not found or inactive in the system.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the EntityType is other than caentity/entity.
     * @throws InvalidEntityAttributeException
     *             thrown when given given attributes of Entity have invalid value.
     */
    List<TreeNode<CAEntity>> getCAHierarchies() throws EntityNotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException;

    /**
     * This method returns CA Hierarchy for CA With Name
     *
     * @return List of {@link TreeNode} object containing CA Hierarchy in tree format.
     * @throws EntityNotFoundException
     *             Throws when Entity is not found or inactive in the system.
     * @throws InvalidEntityException
     *             thrown when the EntityType is other than caentity/entity.
     */
    TreeNode<CAEntity> getCAHierarchyByName(String name) throws EntityNotFoundException, EntityServiceException, InvalidEntityException;

    /**
     * Create a CAEntity/Entity and Get Enrollment info in case of SCEP and CMPV2
     *
     * @param entity
     *            Object of CAEntity/Entity.
     * @param enrollmentType
     *            Type of enrollment.
     * @return EntityEnrollmentInfo with created entity object and EnrollmentInfo.
     *
     * @throws AlgorithmNotFoundException
     *             thrown when given key generation algorithm is not found or inactive.
     * @throws CRLExtensionException
     *             thrown if the the CRL extensions are invalid.
     * @throws CRLGenerationException
     *             thrown when any exception occurred during CRLGeneration.
     * @throws EntityAlreadyExistsException
     *             thrown when Entity or CAEntity already exists.
     * @throws EntityCategoryNotFoundException
     *             thrown when category doesn't exists with the given name.
     * @throws EntityNotFoundException
     *             thrown when entity doesn't exists with the given name.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidCRLGenerationInfoException
     *             thrown if the CRLGenerationInfo Fields are invalid.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when given given attributes of Entity or CAEntity have invalid value.
     * @throws InvalidEntityCategoryException
     *             thrown when the given category is in invalid format.
     * @throws InvalidProfileException
     *             thrown when invalid profile is mapped to Entity or CAEntity
     * @throws InvalidSubjectAltNameExtension
     *             thrown when invalid subject alternative name is given
     * @throws InvalidSubjectException
     *             thrown when invalid subject is given
     * @throws MissingMandatoryFieldException
     *             thrown when any mandatory fields are not given
     * @throws ProfileNotFoundException
     *             thrown if given entity contains the entity profile that doesn't exists.
     * @throws UnsupportedCRLVersionException
     *             thrown if the given CRL version is not supported.
     */
    @Deprecated
    EntityEnrollmentInfo createEntityAndGetEnrollmentInfo(final Entity entity, final EnrollmentType enrollmentType) throws AlgorithmNotFoundException, CRLExtensionException, CRLGenerationException,
            EntityAlreadyExistsException, EntityCategoryNotFoundException, EntityNotFoundException, EntityServiceException, InvalidCRLGenerationInfoException, InvalidEntityException,
            InvalidEntityAttributeException, InvalidEntityCategoryException, InvalidProfileException, InvalidSubjectAltNameExtension, InvalidSubjectException, MissingMandatoryFieldException,
            ProfileNotFoundException, UnsupportedCRLVersionException;

    /**
     * Create a Entity and Get Enrollment info in case of SCEP and CMPV2.
     * 
     * @param entity
     *            Object of CAEntity/Entity.
     * @param enrollmentType
     *            Type of enrollment.
     * @return EntityEnrollmentInfo with created entity object and EnrollmentInfo.
     * 
     * @throws AlgorithmNotFoundException
     *             thrown when given key generation algorithm is not found or inactive.
     * @throws CRLExtensionException
     *             thrown if the the CRL extensions are invalid.
     * @throws EntityAlreadyExistsException
     *             thrown when Entity or CAEntity already exists.
     * @throws EntityCategoryNotFoundException
     *             thrown when category doesn't exists with the given name.
     * @throws EntityNotFoundException
     *             thrown when entity doesn't exists with the given name.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidCRLGenerationInfoException
     *             thrown if the CRLGenerationInfo Fields are invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when given given attributes of Entity or CAEntity have invalid value.
     * @throws InvalidEntityCategoryException
     *             thrown when the given category is in invalid format.
     * @throws InvalidProfileException
     *             thrown when invalid profile is mapped to Entity or CAEntity
     * @throws InvalidSubjectAltNameExtension
     *             thrown when invalid subject alternative name is given
     * @throws InvalidSubjectException
     *             thrown when invalid subject is given
     * @throws MissingMandatoryFieldException
     *             thrown when any mandatory fields are not given
     * @throws OTPException
     *             thrown when any OTP details validation fails
     * @throws ProfileNotFoundException
     *             thrown if given entity contains the entity profile that doesn't exists.
     * @throws UnsupportedCRLVersionException
     *             thrown if the given CRL version is not supported.
     */
    @java.lang.SuppressWarnings("squid:S00100")
    EntityEnrollmentInfo createEntityAndGetEnrollmentInfo_v1(final Entity entity, final EnrollmentType enrollmentType) throws AlgorithmNotFoundException, CRLExtensionException,
            CRLGenerationException, EntityAlreadyExistsException, EntityCategoryNotFoundException, EntityNotFoundException, EntityServiceException, InvalidCRLGenerationInfoException,
            InvalidEntityException, InvalidEntityAttributeException, InvalidEntityCategoryException, InvalidProfileException, InvalidSubjectAltNameExtension, InvalidSubjectException,
            MissingMandatoryFieldException, OTPException, ProfileNotFoundException, UnsupportedCRLVersionException;

    /**
     * Update a Entity and Get Enrollment info in case of SCEP and CMPV2.
     * 
     * @param entity
     *            Object of CAEntity/Entity.
     * @param enrollmentType
     *            Type of enrollment.
     * @return EntityEnrollmentInfo with created entity object and EnrollmentInfo.
     *
     * @throws AlgorithmNotFoundException
     *             thrown when given key generation algorithm is not found or inactive.
     * @throws CRLExtensionException
     *             thrown if the the CRL extensions are invalid.
     * @throws CRLGenerationException
     *             thrown when any exception occurred during CRLGeneration.
     * @throws EntityAlreadyExistsException
     *             thrown when Entity or CAEntity already exists.
     * @throws EntityCategoryNotFoundException
     *             thrown when category doesn't exists with the given name.
     * @throws EntityNotFoundException
     *             thrown when entity doesn't exists with the given name.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidCRLGenerationInfoException
     *             thrown if the CRLGenerationInfo Fields are invalid.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when given given attributes of Entity or CAEntity have invalid value.
     * @throws InvalidEntityCategoryException
     *             thrown when the given category is in invalid format.
     * @throws InvalidProfileException
     *             thrown when invalid profile is mapped to Entity or CAEntity
     * @throws InvalidSubjectAltNameExtension
     *             thrown when invalid subject alternative name is given
     * @throws InvalidSubjectException
     *             thrown when invalid subject is given
     * @throws MissingMandatoryFieldException
     *             thrown when any mandatory fields are not given
     * @throws ProfileNotFoundException
     *             thrown if given entity contains the entity profile that doesn't exists.
     * @throws UnsupportedCRLVersionException
     *             thrown if the given CRL version is not supported.
     */
    @Deprecated
    EntityEnrollmentInfo updateEntityAndGetEnrollmentInfo(final Entity entity, final EnrollmentType enrollmentType) throws AlgorithmNotFoundException, CRLExtensionException, CRLGenerationException,
            EntityAlreadyExistsException, EntityCategoryNotFoundException, EntityNotFoundException, EntityServiceException, InvalidCRLGenerationInfoException, InvalidEntityException,
            InvalidEntityAttributeException, InvalidEntityCategoryException, InvalidProfileException, InvalidSubjectAltNameExtension, InvalidSubjectException, MissingMandatoryFieldException,
            ProfileNotFoundException, UnsupportedCRLVersionException;

    /**
     * Update a Entity and Get Enrollment info in case of SCEP and CMPV2.
     * 
     * @param entity
     *            Object of CAEntity/Entity.
     * @param enrollmentType
     *            Type of enrollment.
     * @return EntityEnrollmentInfo with created entity object and EnrollmentInfo.
     * 
     * @throws AlgorithmNotFoundException
     *             thrown when given key generation algorithm is not found or inactive.
     * @throws CRLExtensionException
     *             thrown if the the CRL extensions are invalid.
     * @throws EntityAlreadyExistsException
     *             thrown when Entity or CAEntity already exists.
     * @throws EntityCategoryNotFoundException
     *             thrown when category doesn't exists with the given name.
     * @throws EntityNotFoundException
     *             thrown when entity doesn't exists with the given name.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidCRLGenerationInfoException
     *             thrown if the CRLGenerationInfo Fields are invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when given given attributes of Entity or CAEntity have invalid value.
     * @throws InvalidEntityCategoryException
     *             thrown when the given category is in invalid format.
     * @throws InvalidProfileException
     *             thrown when invalid profile is mapped to Entity or CAEntity
     * @throws InvalidSubjectAltNameExtension
     *             thrown when invalid subject alternative name is given
     * @throws InvalidSubjectException
     *             thrown when invalid subject is given
     * @throws MissingMandatoryFieldException
     *             thrown when any mandatory fields are not given
     * @throws OTPException
     *             thrown when any OTP details validation fails
     * @throws ProfileNotFoundException
     *             thrown if given entity contains the entity profile that doesn't exists.
     * @throws UnsupportedCRLVersionException
     *             thrown if the given CRL version is not supported.
     */
    @java.lang.SuppressWarnings("squid:S00100")
    EntityEnrollmentInfo updateEntityAndGetEnrollmentInfo_v1(final Entity entity, final EnrollmentType enrollmentType) throws AlgorithmNotFoundException, CRLExtensionException,
            CRLGenerationException, EntityAlreadyExistsException, EntityCategoryNotFoundException, EntityNotFoundException, EntityServiceException, InvalidCRLGenerationInfoException,
            InvalidEntityException, InvalidEntityAttributeException, InvalidEntityCategoryException, InvalidProfileException, InvalidSubjectAltNameExtension, InvalidSubjectException,
            MissingMandatoryFieldException, OTPException, ProfileNotFoundException, UnsupportedCRLVersionException;

    /**
     * Returns the list of TrustedEntityInfos for a given entity Type to Trust distribution point service.
     *
     * @param EntityType
     *            Class of entity to be checked (CAEntity/Entity).
     * @return list of TrustedEntityInfos for a given EntityType. Return empty list if there is no data for given EntityType.
     *
     * @throws CertificateNotFoundException
     *             Thrown if certificate not found for the given entity.
     * @throws EntityNotFoundException
     *             thrown when given Entity or CAEntity is not found.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the EntityType is other than caentity/entity.
     * @throws TrustDistributionPointURLNotFoundException
     *             Thrown if TDPS host address is not found.
     */

    List<TrustedEntityInfo> getTrustedEntitiesInfo(final EntityType entityType) throws CertificateNotFoundException, EntityNotFoundException, EntityServiceException, InvalidEntityException,
            TrustDistributionPointURLNotFoundException;

    /**
     * Returns the list of TrustedEntityInfos for a given entityType and entity Name to Trust distribution point service.
     *
     * @param EntityType
     *            Class of entity to be checked (CAEntity/Entity).
     *
     * @param entityName
     *            This is the entityName for a certificate with certificateStatus is to be published to TDPS.
     *
     * @return list of TrustedEntityInfos for a given EntityType and entityName. Return empty list if there is no data for given EntityType and entityName.
     *
     * @throws CertificateNotFoundException
     *             Thrown if certificate not found for the given entity.
     * @throws EntityNotFoundException
     *             thrown when given Entity or CAEntity is not found.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws TrustDistributionPointURLNotFoundException
     *             Thrown if TDPS host address is not found.
     */

    List<TrustedEntityInfo> getTrustedEntitiesInfo(final EntityType entityType, final String entityName) throws CertificateNotFoundException, EntityNotFoundException, EntityServiceException,
            TrustDistributionPointURLNotFoundException;

    /**
     * Returns the list of TrustedEntityInfos for a given entityType and certificateStatus to Trust distribution point service.
     *
     * @param EntityType
     *            Class of entity to be checked (CAEntity/Entity).
     * @param certificateStatus
     *            Certificate status could be ACTIVE.
     * @return list of TrustedEntityInfos for a given EntityType and CertificateStatus.Return empty list if there is no data for given EntityType and certificateStatus.
     *
     * @throws CertificateNotFoundException
     *             Thrown if certificate not found for the given entity.
     * @throws EntityNotFoundException
     *             thrown when given Entity or CAEntity is not found.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the EntityType is other than caentity/entity.
     * @throws TrustDistributionPointURLNotFoundException
     *             Thrown if TDPS host address is not found.
     */
    List<TrustedEntityInfo> getTrustedEntitiesInfo(final EntityType entityType, final CertificateStatus certificateStatus) throws CertificateNotFoundException, EntityNotFoundException,
            EntityServiceException, InvalidEntityException, TrustDistributionPointURLNotFoundException;

    /**
     * @param entityType
     *            Class of entity to be checked (CAEntity/Entity).
     * @param entityName
     *            This is the entityName for a certificate with certificateStatus is to be published to TDPS.
     * @param certificateStatus
     *            Certificate status is a list of status ACTIVE and INACTIVE of the given entity.
     * @return list of chain of TrustedEntityInfos for a given entityName with given EntityType and CertificateStatus.Return empty list if there is no data.
     * @throws CertificateNotFoundException
     *             Thrown if certificate not found for the given entity.
     * @throws EntityNotFoundException
     *             thrown when given Entity or CAEntity is not found.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws TrustDistributionPointURLNotFoundException
     *             Thrown if TDPS host address is not found.
     */
    List<List<TrustedEntityInfo>> getTrustedEntitiesInfoChain(final EntityType entityType, String entityName, final CertificateStatus... certificateStatus) throws CertificateNotFoundException,
            EntityNotFoundException, EntityServiceException, TrustDistributionPointURLNotFoundException;
}
