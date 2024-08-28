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

package com.ericsson.oss.itpf.security.pki.manager.profilemanagement.ejb;

import java.util.List;

import javax.ejb.EJB;
import javax.ejb.Stateless;
import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.core.annotation.EServiceQualifier;
import com.ericsson.oss.itpf.sdk.instrument.annotation.Profiled;
import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.EventLevel;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.access.control.authorization.EntityManagementAuthorizationManager;
import com.ericsson.oss.itpf.security.pki.manager.access.control.common.types.ActionType;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.exception.log.annotation.ErrorLogAnnotation;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.CRLExtensionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidCRLGenerationInfoException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.UnsupportedCRLVersionException;
import com.ericsson.oss.itpf.security.pki.manager.exception.enrollment.EnrollmentURLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyDeletedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityInUseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.EntityCategoryNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.category.InvalidEntityCategoryException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.OTPException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.InvalidOTPCountException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.InvalidOTPException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.InvalidOtpValidityPeriodException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.OTPExpiredException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.endentity.otp.OTPNotSetException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.SerialNumberNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.exception.trustdistributionpoint.TrustDistributionPointURLNotDefinedException;
import com.ericsson.oss.itpf.security.pki.manager.exception.trustdistributionpoint.TrustDistributionPointURLNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.annotation.InstrumentationAnnotation;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricGroup;
import com.ericsson.oss.itpf.security.pki.manager.instrumentation.types.MetricType;
import com.ericsson.oss.itpf.security.pki.manager.model.EnrollmentInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.EnrollmentType;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityCategory;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityEnrollmentInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.TDPSUrlInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.TreeNode;
import com.ericsson.oss.itpf.security.pki.manager.model.TrustedEntityInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entities;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.EntityManagementService;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.api.ProfileManagementService;
import com.ericsson.oss.itpf.security.pki.manager.profilemanagement.impl.EntitiesManager;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.ValidationService;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ItemType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.OperationType;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.ValidateItem;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.utils.ValidationServiceUtils;

/**
 * This class implements {@link ProfileManagementService}
 *
 */
@Profiled
@Stateless
@EServiceQualifier("1.0.0")
public class EntityManagementServiceBean implements EntityManagementService {

    @Inject
    private EntitiesManager entitiesManager;

    @Inject
    EntityManagementAuthorizationManager entityManagementAuthorizationManager;

    @Inject
    private Logger logger;

    @Inject
    ValidationService validationService;

    @Inject
    ValidationServiceUtils validateServiceUtils;

    @EJB
    BulkImportLocalServiceBean bulkImportLocalServiceBean;

    @Inject
    private SystemRecorder systemRecorder;

    private static final int OTP_VALIDITY_PERIOD_FOR_EXISTING_ENTITIES = -1;

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
     * @throws ProfileNotFoundException
     *             thrown if given entity contains the entity profile that doesn't exists.
     * @throws UnsupportedCRLVersionException
     *             thrown if the given CRL version is not supported.
     */
    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.ENTITYMGMT, metricType = MetricType.CREATE)
    @ErrorLogAnnotation()
    public <T extends AbstractEntity> T createEntity(final T entity) throws AlgorithmNotFoundException, CRLExtensionException, EntityAlreadyExistsException, EntityCategoryNotFoundException,
            EntityServiceException, InvalidCRLGenerationInfoException, InvalidEntityAttributeException, InvalidEntityCategoryException, InvalidProfileException, InvalidSubjectAltNameExtension,
            InvalidSubjectException, MissingMandatoryFieldException, ProfileNotFoundException, UnsupportedCRLVersionException {

        entityManagementAuthorizationManager.authorizeEntityOperations(entity.getType(), ActionType.CREATE);

        logger.debug("Creating entity of Type {} ", entity.getType());

        setOtpValidityPeriod(entity, OTP_VALIDITY_PERIOD_FOR_EXISTING_ENTITIES);

        final ValidateItem validateItem = validateServiceUtils.generateEntityValidateItem(entity.getType(),
                com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.OperationType.CREATE, entity);

        validationService.validate(validateItem);

        final T createdEntity = entitiesManager.createEntity(entity);

        logger.debug("Created entity sucessfully {}", entity.getType());

        return createdEntity;
    }

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
    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.ENTITYMGMT, metricType = MetricType.CREATE)
    @ErrorLogAnnotation()
    public <T extends AbstractEntity> T createEntity_v1(final T entity) throws AlgorithmNotFoundException, CRLExtensionException, EntityAlreadyExistsException, EntityServiceException,
            EntityCategoryNotFoundException, EntityNotFoundException, InvalidCRLGenerationInfoException, InvalidEntityException, InvalidEntityAttributeException, InvalidEntityCategoryException,
            InvalidProfileException, InvalidSubjectAltNameExtension, InvalidSubjectException, MissingMandatoryFieldException, OTPException, ProfileNotFoundException, UnsupportedCRLVersionException {

        entityManagementAuthorizationManager.authorizeEntityOperations(entity.getType(), ActionType.CREATE);

        logger.debug("Creating entity of Type {} ", entity.getType());

        final ValidateItem validateItem = validateServiceUtils.generateEntityValidateItem(entity.getType(), OperationType.CREATE, entity);
        validationService.validate(validateItem);

        final T createdEntity = entitiesManager.createEntity(entity);

        logger.debug("Created {}", entity.getType());

        return createdEntity;
    }

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
    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.ENTITYMGMT, metricType = MetricType.CREATE)
    @ErrorLogAnnotation()
    public EntityEnrollmentInfo createEntityAndGetEnrollmentInfo(final Entity entity, final EnrollmentType enrollmentType) throws AlgorithmNotFoundException, CRLExtensionException,
            EntityAlreadyExistsException, EntityServiceException, EntityCategoryNotFoundException, EntityNotFoundException, InvalidCRLGenerationInfoException, InvalidEntityException,
            InvalidEntityAttributeException, InvalidEntityCategoryException, InvalidProfileException, InvalidSubjectAltNameExtension, InvalidSubjectException, MissingMandatoryFieldException,
            ProfileNotFoundException, UnsupportedCRLVersionException {

        entityManagementAuthorizationManager.authorizeEntityOperations(entity.getType(), ActionType.CREATE);

        final EntityEnrollmentInfo entityEnrollmentInfo = new EntityEnrollmentInfo();

        logger.info("Creating entity of Type {} ", entity.getType());

        setOtpValidityPeriod(entity, OTP_VALIDITY_PERIOD_FOR_EXISTING_ENTITIES);

        final ValidateItem validateItem = validateServiceUtils.generateEntityValidateItem(entity.getType(),
                com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.OperationType.CREATE, entity);

        validationService.validate(validateItem);

        final Entity createdEntity = entitiesManager.createEntity(entity);
        entitiesManager.validateSubject(createdEntity);

        logger.info("Created {}", entity.getType());

        logger.info("Invoking getEnrollmentInfo");
        final EnrollmentInfo enrollInfo = entitiesManager.getEnrollmentInfoForEntity(createdEntity, enrollmentType);
        logger.info("Successfully Invoked getEnrollmentInfo");

        entityEnrollmentInfo.setEntity(createdEntity);
        entityEnrollmentInfo.setEnrollmentInfo(enrollInfo);

        logger.debug("Created entity of Type {}", entity.getType());

        return entityEnrollmentInfo;
    }

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
    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.ENTITYMGMT, metricType = MetricType.CREATE)
    @ErrorLogAnnotation()
    public EntityEnrollmentInfo createEntityAndGetEnrollmentInfo_v1(final Entity entity, final EnrollmentType enrollmentType) throws AlgorithmNotFoundException, CRLExtensionException,
            EntityAlreadyExistsException, EntityServiceException, EntityCategoryNotFoundException, EntityNotFoundException, InvalidCRLGenerationInfoException, InvalidEntityAttributeException,
            InvalidEntityCategoryException, InvalidProfileException, InvalidSubjectAltNameExtension, InvalidSubjectException, MissingMandatoryFieldException, OTPException, ProfileNotFoundException,
            UnsupportedCRLVersionException {

        entityManagementAuthorizationManager.authorizeEntityOperations(entity.getType(), ActionType.CREATE);

        final EntityEnrollmentInfo entityEnrollmentInfo = new EntityEnrollmentInfo();

        logger.info("Creating entity of Type {} ", entity.getType());

        final ValidateItem validateItem = validateServiceUtils.generateEntityValidateItem(entity.getType(), OperationType.CREATE, entity);
        validationService.validate(validateItem);

        final Entity createdEntity = entitiesManager.createEntity(entity);
        entitiesManager.validateSubject(createdEntity);

        logger.info("Created {}", entity.getType());

        logger.info("Invoking getEnrollmentInfo");
        final EnrollmentInfo enrollInfo = entitiesManager.getEnrollmentInfoForEntity(createdEntity, enrollmentType);
        logger.info("Successfully Invoked getEnrollmentInfo");

        entityEnrollmentInfo.setEntity(createdEntity);
        entityEnrollmentInfo.setEnrollmentInfo(enrollInfo);
        logger.debug("Created entity of Type {}", entity.getType());
        return entityEnrollmentInfo;
    }

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
    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.ENTITYMGMT, metricType = MetricType.UPDATE)
    @ErrorLogAnnotation()
    public EntityEnrollmentInfo updateEntityAndGetEnrollmentInfo(final Entity entity, final EnrollmentType enrollmentType) throws AlgorithmNotFoundException, CRLExtensionException,
            EntityAlreadyExistsException, EntityCategoryNotFoundException, EntityNotFoundException, EntityServiceException, InvalidCRLGenerationInfoException, InvalidEntityException,
            InvalidEntityAttributeException, InvalidEntityCategoryException, InvalidProfileException, InvalidSubjectAltNameExtension, InvalidSubjectException, MissingMandatoryFieldException,
            OTPException, ProfileNotFoundException, UnsupportedCRLVersionException {

        entityManagementAuthorizationManager.authorizeEntityOperations(entity.getType(), ActionType.UPDATE);

        final EntityEnrollmentInfo entityEnrollmentInfo = new EntityEnrollmentInfo();

        logger.debug("Updating entity of Type {} ", entity.getType());

        final Entity entityUpdated = entitiesManager.updateEntity(entity);
        entitiesManager.validateSubject(entityUpdated);

        logger.debug("Updated {}", entity.getType());

        logger.debug("Invoking getEnrollmentInfo");
        final EnrollmentInfo enrollInfo = entitiesManager.getEnrollmentInfoForEntity(entityUpdated, enrollmentType);
        logger.debug("Successfully Invoked getEnrollmentInfo");

        entityEnrollmentInfo.setEntity(entityUpdated);
        entityEnrollmentInfo.setEnrollmentInfo(enrollInfo);

        logger.debug("Created entity of Type {}", entity.getType());
        return entityEnrollmentInfo;
    }

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
    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.ENTITYMGMT, metricType = MetricType.UPDATE)
    @ErrorLogAnnotation()
    public EntityEnrollmentInfo updateEntityAndGetEnrollmentInfo_v1(final Entity entity, final EnrollmentType enrollmentType) throws AlgorithmNotFoundException, CRLExtensionException,
            EntityAlreadyExistsException, EntityCategoryNotFoundException, EntityNotFoundException, EntityServiceException, InvalidCRLGenerationInfoException, InvalidEntityAttributeException,
            InvalidEntityCategoryException, InvalidProfileException, InvalidSubjectAltNameExtension, InvalidSubjectException, MissingMandatoryFieldException, OTPException, ProfileNotFoundException,
            UnsupportedCRLVersionException {

        entityManagementAuthorizationManager.authorizeEntityOperations(entity.getType(), ActionType.UPDATE);

        final EntityEnrollmentInfo entityEnrollmentInfo = new EntityEnrollmentInfo();

        logger.debug("Updating entity of Type {} ", entity.getType());

        final Entity entityUpdated = entitiesManager.updateEntity(entity);
        entitiesManager.validateSubject(entityUpdated);

        logger.debug("Updated {}", entity.getType());

        logger.debug("Invoking getEnrollmentInfo");
        final EnrollmentInfo enrollInfo = entitiesManager.getEnrollmentInfoForEntity(entityUpdated, enrollmentType);
        logger.debug("Successfully Invoked getEnrollmentInfo");

        entityEnrollmentInfo.setEntity(entityUpdated);
        entityEnrollmentInfo.setEnrollmentInfo(enrollInfo);

        logger.debug("Created entity of Type {}", entity.getType());
        return entityEnrollmentInfo;
    }

    /**
     * Delete an CAEntity/Entity based on Id/name.
     *
     * <ul>
     * <li>CA Entity can only be deleted, if there are no mappings to any certificate profile.</li>
     * </ul>
     *
     * @param entity
     *            Object of CAEntity/Entity with id/name set.
     * @return Returns object of ProfileManagerResponse class containing operation status, success messages and error messages,if any.
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
    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.ENTITYMGMT, metricType = MetricType.DELETE)
    @ErrorLogAnnotation()
    public <T extends AbstractEntity> void deleteEntity(final T entity) throws EntityAlreadyDeletedException, EntityNotFoundException, EntityInUseException, EntityServiceException,
            InvalidEntityException, InvalidEntityAttributeException {

        entityManagementAuthorizationManager.authorizeEntityOperations(entity.getType(), ActionType.DELETE);

        logger.debug("Deleting {}", entity.getType());

        entitiesManager.deleteEntity(entity);

        logger.debug("Deleted Entity");

    }

    /**
     * Export entities in bulk manner. It returns the entities based on the specified Entity type(CAEntity or Entity).
     *
     * @param entityTypes
     *            Entity Type specifies the type of entities to be exported.It accepts variable arguments namely CAEntity and Entity .
     * @return Entities object containing list of CAEntity/Entity or All.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid profile Attribute is found while mapping Entity
     */
    @Override
    public Entities getEntities(final EntityType... entityTypes) throws EntityServiceException, InvalidEntityException, InvalidEntityAttributeException, InvalidProfileAttributeException {

        final long startTime = System.currentTimeMillis();
        boolean isComplete = false;

        Entities entities = new Entities();

        try {
            for (final EntityType entityType : entityTypes) {
                entityManagementAuthorizationManager.authorizeEntityOperations(entityType, ActionType.READ);
            }

            logger.debug("getEntities by type {} ", new Object[] { entityTypes });

            if (entityTypes.length == 0) {
                throw new IllegalArgumentException(ProfileServiceErrorCodes.NO_ENTITYTYPE_PRESENT);
            }

            entities = entitiesManager.getEntities(entityTypes);
            isComplete = true;
        } finally {
            generateBulkEntitiesEvent(startTime, entities, "EXPORT", isComplete);
        }

        logger.debug("Exported Entities");

        return entities;
    }

    /**
     * Get an Entity based on Id/name.
     *
     * @param entity
     *            Object of CAEntity/Entity with id/name set.
     * @return Object of CAEntity/Entity.
     * @throws EntityNotFoundException
     *             thrown when no entity exists with given id/name and entity profile name.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when given entity has invalid attribute.
     */
    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.ENTITYMGMT, metricType = MetricType.GET)
    @ErrorLogAnnotation()
    public <T extends AbstractEntity> T getEntity(final T entity) throws EntityNotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException {

        entityManagementAuthorizationManager.authorizeEntityOperations(entity.getType(), ActionType.READ);

        logger.debug("Retrieving {}", entity.getType());

        final T entityFound = entitiesManager.getEntity(entity);

        logger.debug("Retrieved {} ", entityFound.getType());

        return entityFound;
    }

    /**
     * Import all entities in bulk manner.
     *
     * @param entities
     *            Entities object containing Entites/CAEntities.
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
    @Override
    public void importEntities(final Entities entities) throws AlgorithmNotFoundException, CRLExtensionException, EntityAlreadyExistsException, EntityCategoryNotFoundException,
            EntityServiceException, InvalidCRLGenerationInfoException, InvalidEntityException, InvalidEntityAttributeException, InvalidEntityCategoryException, InvalidProfileException,
            InvalidSubjectAltNameExtension, InvalidSubjectException, MissingMandatoryFieldException, OTPException, ProfileNotFoundException, UnsupportedCRLVersionException {

        logger.debug("Importing Entities");

        final long startTime = System.currentTimeMillis();
        boolean isComplete = false;

        try {
            if (!ValidationUtils.isNullOrEmpty(entities.getEntities())) {
                for (final Entity entity : entities.getEntities()) {
                    entityManagementAuthorizationManager.authorizeEntityOperations(entity.getType(), ActionType.IMPORT);
                }
            }

            if (!ValidationUtils.isNullOrEmpty(entities.getCAEntities())) {
                for (final CAEntity caEntity : entities.getCAEntities()) {
                    entityManagementAuthorizationManager.authorizeEntityOperations(caEntity.getType(), ActionType.IMPORT);
                }
            }

            bulkImportLocalServiceBean.importEntities(entities);

            isComplete = true;
        } finally {
            generateBulkEntitiesEvent(startTime, entities, "IMPORT", isComplete);
        }

        logger.debug("Imported Entities");
    }

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
     * @throws ProfileNotFoundException
     *             thrown if given entity contains the entity profile that doesn't exists.
     * @throws UnsupportedCRLVersionException
     *             thrown if the given CRL version is not supported.
     */
    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.ENTITYMGMT, metricType = MetricType.UPDATE)
    @ErrorLogAnnotation()
    public <T extends AbstractEntity> T updateEntity(final T entity) throws AlgorithmNotFoundException, CRLExtensionException, EntityAlreadyExistsException, EntityCategoryNotFoundException,
            EntityNotFoundException, EntityServiceException, InvalidCRLGenerationInfoException, InvalidEntityAttributeException, InvalidEntityCategoryException, InvalidProfileException,
            InvalidSubjectAltNameExtension, InvalidSubjectException, MissingMandatoryFieldException, ProfileNotFoundException, UnsupportedCRLVersionException {

        entityManagementAuthorizationManager.authorizeEntityOperations(entity.getType(), ActionType.UPDATE);

        logger.debug("Updating {} ", entity.getType());

        setOtpValidityPeriod(entity, OTP_VALIDITY_PERIOD_FOR_EXISTING_ENTITIES);

        final ValidateItem validateItem = validateServiceUtils.generateEntityValidateItem(entity.getType(),
                com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.OperationType.UPDATE, entity);

        validationService.validate(validateItem);

        final T entityUpdated = entitiesManager.updateEntity(entity);

        logger.debug("Updated {}", entityUpdated.getType());

        return entityUpdated;
    }

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
     * @throws OTPException
     *             thrown when any OTP details validation fails
     * @throws ProfileNotFoundException
     *             thrown if given entity contains the entity profile that doesn't exists.
     * @throws UnsupportedCRLVersionException
     *             thrown if the given CRL version is not supported.
     */
    @Override
    @InstrumentationAnnotation(metricGroup = MetricGroup.ENTITYMGMT, metricType = MetricType.UPDATE)
    @ErrorLogAnnotation()
    public <T extends AbstractEntity> T updateEntity_v1(final T entity) throws AlgorithmNotFoundException, CRLExtensionException, EntityAlreadyExistsException, EntityCategoryNotFoundException,
            EntityNotFoundException, EntityServiceException, InvalidCRLGenerationInfoException, InvalidEntityException, InvalidEntityAttributeException, InvalidEntityCategoryException,
            InvalidProfileException, InvalidSubjectAltNameExtension, InvalidSubjectException, MissingMandatoryFieldException, OTPException, ProfileNotFoundException, UnsupportedCRLVersionException {

        entityManagementAuthorizationManager.authorizeEntityOperations(entity.getType(), ActionType.UPDATE);

        logger.debug("Updating {} ", entity.getType());

        final ValidateItem validateItem = validateServiceUtils.generateEntityValidateItem(entity.getType(), OperationType.UPDATE, entity);
        validationService.validate(validateItem);

        final T entityUpdated = entitiesManager.updateEntity(entity);

        logger.debug("Updated {}", entityUpdated.getType());

        return entityUpdated;
    }

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
    @Override
    @ErrorLogAnnotation()
    public boolean isEntityNameAvailable(final String name, final EntityType entityType) throws EntityServiceException, InvalidEntityException {

        entityManagementAuthorizationManager.authorizeIsEntityNameAvailable();

        return entitiesManager.isNameAvailable(name, entityType);
    }

    /**
     * This method is used in case of SCEP for validating OTP
     *
     * @param entityName
     *            Name of the entity for which otp to be validated.
     * @param otp
     *            is the challenge password of the CSR.
     * @return true/false
     *
     * @return true/false
     * @throws EntityNotFoundException
     *             thrown when given entity doesn't exists.
     * @throws EntityServiceException
     *             Thrown when there are any DB Errors retrieving the Entity Data.
     * @throws OTPExpiredException
     *             thrown when OTP count has reached 0.
     */
    @Override
    @ErrorLogAnnotation()
    public boolean isOTPValid(final String entityName, final String otp) throws EntityNotFoundException, EntityServiceException, OTPExpiredException {

        entityManagementAuthorizationManager.authorizeIsOTPValid();

        return entitiesManager.isOTPValid(entityName, otp);
    }

    /**
     * Get CA/EndEntities by subject specified.
     *
     * @param EntityType
     *            Type of entity (CAEntity/Entity)
     * @param subject
     *            Object of subject class with fields set.
     * @return List of CA/EndEntities objects.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidSubjectException
     *             thrown when invalid subject is given.
     */
    @Override
    @ErrorLogAnnotation()
    public List<? extends AbstractEntity> getEntitiesBySubject(final Subject subject, final EntityType entityType) throws EntityServiceException, InvalidSubjectException {

        entityManagementAuthorizationManager.authorizeEntityOperations(entityType, ActionType.READ);
        // TODO Auto-generated method stub
        return null;
    }

    /**
     * This method id used to get Enrollment info in case of SCEP and CMPV2. This method is usually invoked by CREDM to fetch the EnrollmentDetails.This method accepts Entity object which contains
     * atleast entityname and EntityType as inputs and returns the EnrollmentInfo object to CREDM
     *
     *
     * @param enrollmentType
     *            Type of enrollment.
     * @param entity
     *            Object of entity with required fields filled.
     * @return EnrollementInfo object containing the CA certificate, enrollment URL and Trust Distribution URL.
     * @throws EntityNotFoundException
     *             thrown when given entity doesn't exists.
     * @throws EntityServiceException
     *             Thrown when there are any DB Errors retrieving the Entity Data.
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
     *
     */
    @Override
    @ErrorLogAnnotation()
    public EnrollmentInfo getEnrollmentInfo(final EnrollmentType enrollmentType, final Entity entity) throws EntityNotFoundException, EntityServiceException, EnrollmentURLNotFoundException,
            InvalidEntityException, InvalidEntityAttributeException, OTPExpiredException, TrustDistributionPointURLNotFoundException {

        entityManagementAuthorizationManager.authorizeGetEnrollmentInfo();
        return entitiesManager.getEnrollmentInfoForEntity(entity, enrollmentType);
    }

    /**
     * Bulk deletion of entities of any type based on id or name.To delete any entity, id/name should be set in the list of Entity/CAEntity objects and sent as Entities.
     *
     * @param entities
     *            Contains list of Entity,CAEntity objects with id/name filled.
     * @throws EntityAlreadyDeletedException
     *             thrown when given entity is already deleted.
     * @throws EntityInUseException
     *             thrown when given entity to be deleted is in use by other profiles.
     * @throws EntityNotFoundException
     *             thrown when no entity exists with given id/name.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when given entity has invalid attribute.
     */
    @Override
    public void deleteEntities(final Entities entities) throws EntityAlreadyDeletedException, EntityInUseException, EntityNotFoundException, EntityServiceException, InvalidEntityException,
            InvalidEntityAttributeException {

        logger.debug("Deleting Entities in Bulk");

        final long startTime = System.currentTimeMillis();
        boolean isComplete = false;

        try {
            if (!ValidationUtils.isNullOrEmpty(entities.getEntities())) {
                for (final Entity entity : entities.getEntities()) {
                    entityManagementAuthorizationManager.authorizeEntityOperations(entity.getType(), ActionType.DELETE);
                    entitiesManager.deleteEntity(entity);
                }
            }

            if (!ValidationUtils.isNullOrEmpty(entities.getCAEntities())) {
                for (final CAEntity caEntity : entities.getCAEntities()) {
                    entityManagementAuthorizationManager.authorizeEntityOperations(caEntity.getType(), ActionType.DELETE);
                    entitiesManager.deleteEntity(caEntity);
                }
            }

            isComplete = true;
        } finally {
            generateBulkEntitiesEvent(startTime, entities, "DELETE", isComplete);
        }
    }

    /**
     * Update entities in bulk manner.
     *
     * @param entities
     *            Entities object containing Entites/CAEntities to be updated.
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
    @Override
    public void updateEntities(final Entities entities) throws AlgorithmNotFoundException, CRLExtensionException, EntityAlreadyExistsException, EntityCategoryNotFoundException,
            EntityNotFoundException, EntityServiceException, InvalidCRLGenerationInfoException, InvalidEntityException, InvalidEntityAttributeException, InvalidEntityCategoryException,
            InvalidProfileException, InvalidSubjectAltNameExtension, InvalidSubjectException, MissingMandatoryFieldException, OTPException, ProfileNotFoundException, UnsupportedCRLVersionException {
        logger.debug("Updating Entities in Bulk");

        final long startTime = System.currentTimeMillis();
        boolean isComplete = false;

        try {
            if (!ValidationUtils.isNullOrEmpty(entities.getEntities())) {
                for (final Entity entity : entities.getEntities()) {
                    entityManagementAuthorizationManager.authorizeEntityOperations(entity.getType(), ActionType.UPDATE);
                    final ValidateItem validateItem = validateServiceUtils.generateEntityValidateItem(entity.getType(),
                            com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.OperationType.UPDATE, entity);
                    validationService.validate(validateItem);

                    entitiesManager.updateEntity(entity);
                }
            }

            if (!ValidationUtils.isNullOrEmpty(entities.getCAEntities())) {
                for (final CAEntity caEntity : entities.getCAEntities()) {
                    entityManagementAuthorizationManager.authorizeEntityOperations(caEntity.getType(), ActionType.UPDATE);
                    final ValidateItem validateItem = validateServiceUtils.generateEntityValidateItem(caEntity.getType(),
                            com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.OperationType.UPDATE, caEntity);
                    validationService.validate(validateItem);
                    entitiesManager.updateEntity(caEntity);
                }
            }

            isComplete = true;
        } finally {
            generateBulkEntitiesEvent(startTime, entities, "UPDATE", isComplete);
        }
    }

    /**
     * This method is used to update OTP and OTP Count.
     *
     * @param entityName
     *            Name of the entity for which otp to be retrieved.
     * @param otp
     *            OTP to be updated
     * @param otpCount
     *            OTPCount, as to when will OTP be expired.
     *
     * @throws EntityNotFoundException
     *             thrown when entity is not found with the given entityName.
     * @throws EntityServiceException
     *             thrown when entity can not be retrieved from DB.
     * @throws InvalidEntityException
     *             thrown if the given entity is invalid.
     * @throws InvalidOTPCountException
     *             thrown when OTP count exceeds 5 or is negative.
     * @throws InvalidOTPException
     *             when OTP passed is null.
     */
    @Override
    @ErrorLogAnnotation()
    public void updateOTP(final String entityName, final String oTP, final int oTPCount) throws EntityNotFoundException, EntityServiceException, InvalidEntityException, InvalidOTPCountException,
            InvalidOTPException {

        entityManagementAuthorizationManager.authorizeOTPOperations(ActionType.UPDATE);
        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setName(entityName);
        entityInfo.setOTPCount(oTPCount);
        entityInfo.setOTP(oTP);

        final Entity entity = new Entity();
        entity.setOtpValidityPeriod(OTP_VALIDITY_PERIOD_FOR_EXISTING_ENTITIES);
        entity.setEntityInfo(entityInfo);
        entitiesManager.updateOTP(entity);

        systemRecorder.recordSecurityEvent("Entity Management Service", "EntityManagementServiceBean", "Entity " + entityName + "otp updated ", "ENTITYMANAGEMENT.UPDATE_OTP",
                ErrorSeverity.INFORMATIONAL, "SUCCESS");

    }

    /**
     * This method is used to update OTP, OTP Count and OTP Validity Period.
     *
     * @param entityName
     *            Name of the entity for which otp to be retrieved.
     * @param otp
     *            OTP to be updated
     * @param otpCount
     *            OTPCount, as to when will OTP be expired.
     * @param otpValidityPeriod
     *            Time period in minutes after which OTP expires
     * @throws EntityNotFoundException
     *             thrown when entity is not found with the given entityName.
     * @throws EntityServiceException
     *             thrown when entity can not be retrieved from DB.
     * @throws InvalidOTPCountException
     *             thrown when OTP count exceeds 5 or is negative.
     * @throws InvalidOTPException
     *             when OTP passed is null.
     * @throws InvalidOtpValidityPeriodException
     *             thrown if the OTPValidityPeriod Field is invalid.
     */
    @Override
    @ErrorLogAnnotation()
    public void updateOTP(final String entityName, final String otp, final int otpCount, final int otpValidityPeriod) throws EntityNotFoundException, EntityServiceException, InvalidOTPCountException,
            InvalidOTPException, InvalidOtpValidityPeriodException {

        entityManagementAuthorizationManager.authorizeOTPOperations(ActionType.UPDATE);
        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setName(entityName);
        entityInfo.setOTPCount(otpCount);
        entityInfo.setOTP(otp);

        final Entity entity = new Entity();
        entity.setOtpValidityPeriod(otpValidityPeriod);
        entity.setEntityInfo(entityInfo);

        final ValidateItem otpValidateItem = validateServiceUtils.generateOtpValidateItem(ItemType.ENTITY_OTP, OperationType.UPDATE, entity);
        validationService.validate(otpValidateItem);

        entitiesManager.updateOTP(entity);

        systemRecorder.recordSecurityEvent("Entity Management Service", "EntityManagementServiceBean", "Entity " + entityName + "otp updated ", "ENTITYMANAGEMENT.UPDATE_OTP",
                ErrorSeverity.INFORMATIONAL, "SUCCESS");

    }

    /**
     * This method is used to get OTP.
     *
     * @param entityName
     *            Name of the entity for which OTP is to be retrieved.
     * @return otp
     *
     * @throws EntityNotFoundException
     *             thrown when given entity doesn't exist.
     * @throws EntityServiceException
     *             thrown when any internal Database errors while retrieving entity by Name.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws OTPExpiredException
     *             thrown when otpCount decreases to 0
     * @throws OTPNotSetException
     *             thrown when OTP is not Set in the Entity.
     */
    @Override
    @ErrorLogAnnotation()
    public String getOTP(final String entityName) throws EntityServiceException, EntityNotFoundException, InvalidEntityException, OTPNotSetException, OTPExpiredException {

        entityManagementAuthorizationManager.authorizeOTPOperations(ActionType.READ);

        final EntityInfo entityInfo = new EntityInfo();
        entityInfo.setName(entityName);

        final Entity entity = new Entity();
        entity.setEntityInfo(entityInfo);

        final ValidateItem otpValidateItem = validateServiceUtils.generateOtpValidateItem(ItemType.ENTITY_OTP, OperationType.VALIDATE, entity);
        validationService.validate(otpValidateItem);

        return entitiesManager.getOtp(entity);

    }

    /**
     * Get an Entity based on category.
     *
     * @param entityCategory
     * @return List of entities based on category
     *
     * @throws EntityCategoryNotFoundException
     *             Thrown when any internal error occurs in system.
     * @throws EntityNotFoundException
     *             thrown when given entity doesn't exist.
     * @throws EntityServiceException
     *             thrown when any internal Database errors while retrieving entity by Name.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws InvalidEntityCategoryException
     *             thrown when the given entity category is invalid.
     */
    @Override
    @ErrorLogAnnotation()
    public List<Entity> getEntitiesByCategory(final EntityCategory entityCategory) throws EntityCategoryNotFoundException, EntityServiceException, InvalidEntityException,
            InvalidEntityAttributeException, InvalidEntityCategoryException {

        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.ENTITY, ActionType.READ);

        logger.info("Get entities by category");
        return entitiesManager.getEntitiesByCategory(entityCategory, true);
    }

    /**
     * Get an Entity based on category without issuer certificates data.
     *
     * @param entityCategory
     * @return List of entities based on category
     * @throws EntityCategoryNotFoundException
     *             Thrown when any internal error occurs in system.
     * @throws EntityNotFoundException
     *             thrown when given entity doesn't exist.
     * @throws EntityServiceException
     *             thrown when any internal Database errors while retrieving entity by Name.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws InvalidEntityCategoryException
     *             thrown when the given entity category is invalid.
     */
    @Override
    @ErrorLogAnnotation()
    public List<Entity> getEntitiesByCategoryv1(final EntityCategory entityCategory)
            throws EntityCategoryNotFoundException, EntityServiceException, InvalidEntityException,
            InvalidEntityAttributeException, InvalidEntityCategoryException {

        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.ENTITY, ActionType.READ);

        logger.info("Get entities by category v1");
        return entitiesManager.getEntitiesByCategory(entityCategory, false);
    }

    /**
     * Get an Entity based on category.
     *
     * @param entityCategory
     * @return List of entities based on category
     * @throws EntityCategoryNotFoundException
     *             Thrown when any internal error occurs in system.
     * @throws EntityNotFoundException
     *             thrown when given entity doesn't exist.
     * @throws EntityServiceException
     *             thrown when any internal Database errors while retrieving entity by Name.
     * @throws InvalidEntityException
     *             thrown when the given entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     * @throws InvalidEntityCategoryException
     *             thrown when the given entity category is invalid.
     */
    @Override
    @ErrorLogAnnotation()
    public List<Entity> getEntitiesSummaryByCategory(final EntityCategory entityCategory) throws EntityCategoryNotFoundException,
            EntityServiceException, InvalidEntityException, InvalidEntityAttributeException, InvalidEntityCategoryException {

        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.ENTITY, ActionType.READ);

        logger.info("Get entities summary by category");
        return entitiesManager.getEntitiesSummaryByCategory(entityCategory);
    }

    // TORF-57958 BEGIN
    /**
     * This method is used to get EntityName By IssuerName And SerialNumber.
     *
     * @param IssuerName
     *            Name of the issuer.
     * @param SerialNumber
     *            SerialNumber of the certificate
     * @return EntityName Name of the Entity
     * @throws CANotFoundException
     *             thrown when given issuer doesn't exist.
     * @throws EntityServiceException
     *             thrown when any internal Database errors while retrieving entity.
     * @throws InvalidEntityException
     *             thrown when the EntityType is other than caentity/entity.
     * @throws SerialNumberNotFoundException
     *             thrown when given SerialNumber doesn't exist.
     */
    @Override
    @ErrorLogAnnotation()
    public String getEntityNameByIssuerNameAndSerialNumber(final String issuerName, final String serialNumber) throws CANotFoundException, EntityServiceException, InvalidEntityException,
            SerialNumberNotFoundException {

        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.ENTITY, ActionType.READ);

        logger.info("Retrieve entityName by CA Name {} and Serial Number {} ", issuerName, serialNumber);

        return entitiesManager.getEntityNameByCaNameAndSerialNumber(issuerName, serialNumber);

    }

    /**
     * This method is used to get List of EntityName(s) By IssuerName.
     *
     * @param IssuerName
     *            Name of the issuer.
     * @return List of EntityName Names of the Entities signed by the selected issuer
     * @throws CANotFoundException
     *             thrown when given issuer doesn't exist.
     * @throws EntityServiceException
     *             thrown when any internal Database errors while retrieving entity.
     * @throws InvalidEntityException
     *             thrown when the EntityType is other than caentity/entity.
     */
    @Override
    @ErrorLogAnnotation()
    public List<String> getEntityNameListByIssuerName(final String issuerName) throws CANotFoundException, EntityServiceException, InvalidEntityException {

        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.ENTITY, ActionType.READ);

        logger.info("Retrieve entityNameList by CA Name {} ", issuerName);

        return entitiesManager.getEntityNameListByIssuerName(issuerName);

    }

    /**
     * This method is used to get List of EntityName(s) By associated trustProfile.
     *
     * @param trustProfileName
     *            Name of the associated trust profile.
     * @return List of EntityName Names of the Entities signed by the selected issuer
     * @throws InvalidEntityException
     *             thrown when the entity is invalid.
     * @throws EntityServiceException
     *             thrown when any internal Database errors while retrieving entity.
     * @throws ProfileNotFoundException
     *             thrown when given trustProfile doesn't exist.
     */
    @Override
    @ErrorLogAnnotation()
    public List<String> getEntityNameListByTrustProfileName(final String trustProfileName) throws InvalidEntityException, EntityServiceException, ProfileNotFoundException {

        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.ENTITY, ActionType.READ);

        logger.info("Retrieve entityNameList by Trust Profile Name {} ", trustProfileName);

        return entitiesManager.getEntityNameListByTrustProfileName(trustProfileName);

    }

    /**
     * This method is used to get List of Entity(s) By IssuerName.
     *
     * @param IssuerName
     *            Name of the issuer.
     * @return List of Entity Entities signed by the selected issuer
     * @throws CANotFoundException
     *             thrown when given issuer doesn't exist.
     * @throws EntityServiceException
     *             thrown when any internal Database errors while retrieving entity.
     * @throws InvalidEntityException
     *             thrown when the EntityType is other than caentity/entity.
     */
    @Override
    @ErrorLogAnnotation()
    public List<Entity> getEntityListByIssuerName(final String issuerName) throws CANotFoundException, EntityServiceException, InvalidEntityException {

        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.ENTITY, ActionType.READ);

        logger.info("Retrieve entityList by CA Name {} ", issuerName);

        return entitiesManager.getEntityListByIssuerName(issuerName);
    }

    // TORF-57958 END

    /**
     * This method is used to return TrustDistributionPointService URL for the given entity.
     *
     * @param entity
     *            Entity for which TrustDistribution URL has to be retrieved.
     * @param issuerName
     *            Name of the issuer in PKI system for the given entity
     * @param certificateStatus
     *            whether certificate is an ACTIVE or INACIVE Certificate.
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
    @Override
    @ErrorLogAnnotation()
    public <T extends AbstractEntity> String getTrustDistributionPointUrl(final T entity, final String issuerName, final CertificateStatus certificateStatus) throws EntityNotFoundException,
            EntityServiceException, TrustDistributionPointURLNotDefinedException, TrustDistributionPointURLNotFoundException {

        entityManagementAuthorizationManager.authorizeEntityOperations(entity.getType(), ActionType.READ);

        return entitiesManager.getTrustDistributionPointUrl(entity, issuerName, certificateStatus);
    }

    /**
     * This method is used to return TDPSUrlInfo object which contains both IPv4 and IPv6 TDPS urls for the Certificate which is identified by the given entity, issuerName and certificateStatus.
     *
     * @param entity
     *            Entity for which TrustDistribution IPV4 and IPV6 URLs have to be returned.
     * @param issuerName
     *            IssuerName of the entity certificate for which TrustDistribution IPV4 and IPV6 URLs have to be returned.
     * @param certificateStatus
     *            Certificate status which could be either ACTIVE or INACTIVE.
     * @return TDPSUrlInfo object it contains IPv4 and IPv6 TDPS urls.
     * @throws EntityNotFoundException
     *             thrown when given Entity or CAEntity is not found.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws TrustDistributionPointURLNotDefinedException
     *             thrown when TrustDistribution Publish Flag is not set.
     * @throws TrustDistributionPointURLNotFoundException
     *             thrown when TrustDistributionURL is not retrieved for the certificate which is identified by the given entity, issuer name and certificate status.
     */
    @Override
    @ErrorLogAnnotation()
    public <T extends AbstractEntity> TDPSUrlInfo getTrustDistributionPointUrls(final T entity, final String issuerName, final CertificateStatus certificateStatus) throws EntityNotFoundException,
            EntityServiceException, TrustDistributionPointURLNotDefinedException, TrustDistributionPointURLNotFoundException {

        entityManagementAuthorizationManager.authorizeEntityOperations(entity.getType(), ActionType.READ);

        return entitiesManager.getTrustDistributionPointUrls(entity, issuerName, certificateStatus);
    }

    /**
     * This method returns CA Hierarchies for each root CA
     *
     * @return List of {@link TreeNode} object containing CA Hierarchies in tree format.
     * @throws CANotFoundException
     *             Throws when RootCA is not found or inactive in the system.
     * @throws EntityServiceException
     *             throws when any internal system error occurs while forming hierarchy.
     * @throws InvalidEntityException
     *             thrown when the EntityType is other than caentity/entity.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     */
    @Profiled
    @Override
    @ErrorLogAnnotation()
    public List<TreeNode<CAEntity>> getCAHierarchies() throws CANotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException {

        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.READ);

        logger.debug("Forming CA hierarchy for root CAs");

        final List<TreeNode<CAEntity>> cAHierarchies = entitiesManager.getCAHierarchies();

        logger.debug("Formed CA hierarchy for root CAs");

        return cAHierarchies;
    }

    /**
     * Get CA Hierarchy from given CA Name.
     *
     * @param entityName
     *            : name of the CA entity from which hierarchy need to be displayed.
     * @return TreeNode containing Hierarchy from given CA Entity
     * @throws CANotFoundException
     *             thrown when no CA is present in Database with given name.
     * @throws EntityServiceException
     *             throws when any internal system error occurs while forming hierarchy.
     * @throws InvalidEntityException
     *             thrown when the EntityType is other than caentity/entity.
     * @throws InvalidEntityAttributeException
     *             thrown when the given entity has invalid attribute.
     */
    @Profiled
    @Override
    @ErrorLogAnnotation()
    public TreeNode<CAEntity> getCAHierarchyByName(final String entityName) throws CANotFoundException, EntityServiceException, InvalidEntityException, InvalidEntityAttributeException {

        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.READ);

        logger.debug("Forming CA hierarchy for CA with name: {}", entityName);

        final TreeNode<CAEntity> cAHierarchy = entitiesManager.getCAHierarchyByName(entityName);

        logger.debug("Formed CA hierarchy for CA with name: {}", entityName);

        return cAHierarchy;
    }

    /**
     * This method will returns the list of TrustedEntityInfos for a given entity Type to Trust distribution point service.
     *
     * @param EntityType
     *            Class of entity to be checked (CAEntity/Entity).
     *
     * @return list of TrustedEntityInfos for a given EntityType.
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

    @Override
    @ErrorLogAnnotation()
    public List<TrustedEntityInfo> getTrustedEntitiesInfo(final EntityType entityType) throws CertificateNotFoundException, EntityNotFoundException, EntityServiceException, InvalidEntityException,
            TrustDistributionPointURLNotFoundException {

        entityManagementAuthorizationManager.authorizeEntityOperations(entityType, ActionType.READ);

        return entitiesManager.getTrustedEntityInfosByTypeAndStatus(entityType, CertificateStatus.ACTIVE, CertificateStatus.INACTIVE);
    }

    /**
     * This method will returns the list of TrustedEntityInfos for a given entityType and entity Name to Trust distribution point service.
     *
     * @param EntityType
     *            Class of entity to be checked (CAEntity/Entity).
     *
     * @param entityName
     *            This is the entityName for a certificate with certificateStatus is to be published to TDPS.
     *
     * @return list of TrustedEntityInfos for a given EntityType and entityName.
     *
     * @throws CertificateNotFoundException
     *             Thrown if certificate not found for the given entity.
     * @throws EntityNotFoundException
     *             thrown when given Entity or CAEntity is not found.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws TrustDistributionPointURLNotFoundException
     *             Thrown if TDPS host address is not found.
     *
     */

    @Override
    @ErrorLogAnnotation()
    public List<TrustedEntityInfo> getTrustedEntitiesInfo(final EntityType entityType, final String entityName) throws CertificateNotFoundException, EntityNotFoundException, EntityServiceException,
            InvalidEntityException, TrustDistributionPointURLNotFoundException {
        entityManagementAuthorizationManager.authorizeEntityOperations(entityType, ActionType.READ);
        return entitiesManager.getTrustedEntityInfosByTypeAndName(entityType, entityName);
    }

    /**
     * This method will returns the list of TrustedEntityInfos for a given entityType and certificateStatus to Trust distribution point service.
     *
     * @param EntityType
     *            Class of entity to be checked (CAEntity/Entity).
     * @param certificateStatus
     *            Certificate status could be ACTIVE.
     * @return list of TrustedEntityInfos for a given EntityType and CertificateStatus.
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

    @Override
    @ErrorLogAnnotation()
    public List<TrustedEntityInfo> getTrustedEntitiesInfo(final EntityType entityType, final CertificateStatus certificateStatus) throws CertificateNotFoundException, EntityNotFoundException,
            EntityServiceException, InvalidEntityException, TrustDistributionPointURLNotFoundException {
        entityManagementAuthorizationManager.authorizeEntityOperations(entityType, ActionType.READ);
        return entitiesManager.getTrustedEntityInfosByTypeAndStatus(entityType, certificateStatus);
    }

    /**
     * This method will returns the list of TrustedEntityInfos for a given entityType and entity Name to Trust distribution point service.
     *
     * @param EntityType
     *            Class of entity to be checked (CAEntity/Entity).
     *
     * @param entityName
     *            This is the entityName for a certificate with certificateStatus is to be published to TDPS.
     *
     * @return list of TrustedEntityInfos for a given EntityType and entityName.
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

    @Override
    @ErrorLogAnnotation()
    public List<List<TrustedEntityInfo>> getTrustedEntitiesInfoChain(final EntityType entityType, final String entityName, final CertificateStatus... certificateStatus)
            throws CertificateNotFoundException, EntityNotFoundException, EntityServiceException, TrustDistributionPointURLNotFoundException {
        entityManagementAuthorizationManager.authorizeEntityOperations(EntityType.CA_ENTITY, ActionType.READ);
        return entitiesManager.getTrustedEntityInfosChainByTypeAndName(entityType, entityName, certificateStatus);
    }

    private void generateBulkEntitiesEvent(final long startTime, final Entities entities, final String operationType, final boolean isSuccess) {
        final String status = isSuccess ? "SUCCESS" : "FAILURE";
        int entitiesCount = 0, caEntitiesCount = 0;

        if (!ValidationUtils.isNullOrEmpty(entities.getEntities())) {
            entitiesCount = entities.getEntities().size();
        }

        if (!ValidationUtils.isNullOrEmpty(entities.getCAEntities())) {
            caEntitiesCount = entities.getCAEntities().size();
        }

        systemRecorder.recordEvent("ENTITYMANAGEMENT.BULK_ENTITIES", EventLevel.COARSE, "PKI", "PKIManager", "BulkEntities [OperationType=" + operationType + ", StartTime=" + startTime + ", EndTime="
                + System.currentTimeMillis() + ", Duration=" + (System.currentTimeMillis() - startTime) + ", CAEntityRequests=" + caEntitiesCount + ", EntityRequests=" + entitiesCount + ", Status="
                + status + "]");
    }

    /**
     * Sets the OTP Validity Period value to the Entity
     *
     * @param entity
     *            Object of CA Entity or Entity.
     * @param otpValidityPeriod
     *            Time period in minutes after which OTP expires
     */
    private <T extends AbstractEntity> void setOtpValidityPeriod(final T entity, final Integer otpValidityPeriod) {

        logger.info("Value of otpValidityPeriod before {} ", otpValidityPeriod);

        if (entity instanceof Entity) {
            ((Entity) entity).setOtpValidityPeriod(otpValidityPeriod);
        }
    }

    /**
     * Get an Entity based on Id/name.
     *
     * @param entity
     *            Object of CAEntity/Entity with id/name set.
     * @return Object of CAEntity/Entity.
     * @throws EntityNotFoundException
     *             thrown when no entity exists with given id/name and entity profile name.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when given entity has invalid attribute.
     */
    @Override
    public <T extends AbstractEntity> T getEntityForImport(final T entity) throws EntityNotFoundException, EntityServiceException, InvalidEntityException,
            InvalidEntityAttributeException {
        entityManagementAuthorizationManager.authorizeEntityOperations(entity.getType(), ActionType.READ);

        logger.debug("Retrieving {}", entity.getType());

        final T entityFound = entitiesManager.getEntityForImport(entity);

        logger.debug("Retrieved {} ", entityFound.getType());

        return entityFound;
    }

    /**
     * Export entities in bulk manner. It returns the entities based on the specified Entity type(CAEntity or Entity).
     *
     * @param entityTypes
     *            Entity Type specifies the type of entities to be exported.It accepts variable arguments namely CAEntity and Entity .
     * @return Entities object containing list of CAEntity/Entity or All.
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * @throws InvalidEntityException
     *             thrown when the entity is invalid.
     * @throws InvalidEntityAttributeException
     *             thrown when Invalid Attribute is found while mapping Entity
     * @throws InvalidProfileAttributeException
     *             thrown when Invalid profile Attribute is found while mapping Entity
     */
    @Override
    public Entities getEntitiesForImport(final EntityType... entityTypes) throws EntityServiceException, InvalidEntityException,
            InvalidEntityAttributeException {
        final long startTime = System.currentTimeMillis();
        boolean isComplete = false;

        Entities entities = new Entities();

        try {
            for (final EntityType entityType : entityTypes) {
                entityManagementAuthorizationManager.authorizeEntityOperations(entityType, ActionType.READ);
            }

            logger.debug("getEntities by type {} ", new Object[] { entityTypes });

            if (entityTypes.length == 0) {
                throw new IllegalArgumentException(ProfileServiceErrorCodes.NO_ENTITYTYPE_PRESENT);
            }

            entities = entitiesManager.getEntitiesForImport(entityTypes);
            isComplete = true;
        } finally {
            generateBulkEntitiesEvent(startTime, entities, "EXPORT", isComplete);
        }

        logger.debug("Exported Entities");

        return entities;
    }

}
