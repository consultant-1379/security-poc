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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.common.entity;

import java.util.ArrayList;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;

import javax.inject.Inject;
import javax.persistence.PersistenceException;
import javax.persistence.Table;
import javax.xml.datatype.Duration;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameField;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.EntitiesPersistenceHandlerFactory;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.entity.EntitiesPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.EntityServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.InvalidEntityAttributeException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.InvalidProfileException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.CertificateExpiryNotificationDetails;
import com.ericsson.oss.itpf.security.pki.manager.model.NotificationSeverity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.AbstractEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.EntityProfileData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectAltNameValidator;

/**
 * This abstract class contains common methods that are used by all entities validators to populate some objects from database. This class is extended by all entity validators.
 * 
 * @author xtelsow
 */
public abstract class AbstractEntityValidator {

    @Inject
    protected Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    protected EntitiesPersistenceHandlerFactory entitiesPersistenceHandlerFactory;

    @Inject
    SubjectAltNameValidator subjectAltNameValidator;

    private static final String NAME_REGEX = "^[a-zA-Z0-9_.-]{3,255}$";

    private static final String ACTIVE = "active";
    private static final String NAME = "name";

    protected static final String OVERRIDING_OPERATOR = "?";

    protected abstract EntitiesPersistenceHandler<? extends AbstractEntity> getEntitiesPersistenceHandler();

    /**
     * Method for verifying the entity name format
     * 
     * @param entityName
     *            name to be checked
     * @throws InvalidEntityAttributeException
     *             when the name given is not in valid format.
     */
    protected void checkEntityNameFormat(final String entityName) throws InvalidEntityAttributeException {
        if (!ValidationUtils.validatePattern(NAME_REGEX, entityName)) {
            logger.error(ProfileServiceErrorCodes.ERR_INVALID_NAME_FORMAT + "{} ", entityName);
            throw new InvalidEntityAttributeException(ProfileServiceErrorCodes.ERR_INVALID_NAME_FORMAT + " " + entityName);
        }
    }

    /**
     * Method for checking the availability of entity name
     * 
     * @param entityName
     *            name to be checked
     * 
     * @param entity
     *            Class of {@link CAEntity}/ {@link Entity}
     * 
     * @param namePath
     *            Path of the 'name' attribute in JPAEntity.
     * 
     * @throws EntityAlreadyExistsException
     *             thrown when trying to create an entity that already exists.
     * 
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * 
     */
    protected <T> void checkNameAvailability(final String entityName, final Class<T> entity, final String namePath) throws EntityAlreadyExistsException, EntityServiceException {

        final String entityType = entity.getAnnotation(Table.class).name();
        try {
            if (!(persistenceManager.findEntityByName(entity, entityName, namePath) == null)) {
                logger.error("{} with name {} already exists", entityType, entityName);
                throw new EntityAlreadyExistsException(entityType + " with name " + entityName + " already exists");
            }
        } catch (final PersistenceException persistenceException) {
            logger.error("Error while checking database if name {} exists in {}.", entityName, entityType);
            throw new EntityServiceException("Error while checking database if name " + entityName + " exists in " + entity.getAnnotation(Table.class).name(), persistenceException);
        }
    }

    /**
     * Method for retrieving the entity data from database
     * 
     * @param id
     *            the primary key using which the respective entity can be fetched
     * 
     * @param entity
     *            Class of {@link CAEntity}/ {@link Entity}
     * 
     * @return generic entity object which contains the data related to caentity/entity
     * 
     * @throws EntityNotFoundException
     *             thrown when no entity exists with given id/name and entity profile name.
     * 
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public <T> T getEntityDataById(final long id, final Class<T> entity) throws EntityNotFoundException, EntityServiceException {

        final T entityData = getEntitiesPersistenceHandler().getEntityById(id, entity);
        return entityData;
    }

    /**
     * Method for checking the entity name for updating the name
     * 
     * @param givenName
     *            Name to be checked in update operation
     * 
     * @param actualName
     *            Actual name retrieved from DB
     * 
     * @param entityClazz
     *            the class name of entity
     * 
     * @param namePath
     *            Path of the 'name' attribute in JPAEntity.
     * 
     * @throws EntityAlreadyExistsException
     *             thrown when trying to create an entity that already exists.
     * 
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public <T> void checkEntityNameForUpdate(final String givenName, final String actualName, final Class<T> entity, final String namePath) throws EntityAlreadyExistsException, EntityServiceException {

        if (!actualName.equalsIgnoreCase(givenName)) {
            checkNameAvailability(givenName, entity, namePath);
        }
    }

    /**
     * This method fetches EntityProfileData from database using profileName
     * 
     * @param profileName
     *            entity profile name
     * 
     * @return EntityProfileData from database
     * 
     * @throws EntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     * 
     * @throws ProfileNotFoundException
     *             thrown when given EntityProfile inside CA Entity/Entity doesn't exist or in inactive state.
     */
    public EntityProfileData getEntityProfileFromDB(final String profileName) throws EntityServiceException, ProfileNotFoundException {
        final Map<String, Object> inputs = new HashMap<String, Object>();
        inputs.put(NAME, profileName);
        inputs.put(ACTIVE, Boolean.TRUE);

        final EntityProfileData profileData = getEntitiesPersistenceHandler().getEntityWhere(EntityProfileData.class, inputs);

        if (profileData == null) {
            logger.error("Entity Profile {} {}", ProfileServiceErrorCodes.NOT_FOUND_WITH_NAME, profileName);
            throw new ProfileNotFoundException("Entity Profile" + ProfileServiceErrorCodes.NOT_FOUND_WITH_NAME + profileName);
        }

        return profileData;
    }

    /**
     * This method validates subjectAltNameString and fetches the SubjectAltNameFields from json object
     * 
     * @param entityProfileData
     *            which is fetched from database using entityprofile name from CA Entity/Entity
     * @return set of SubjectAltNameFieldTypes
     * @throws InvalidSubjectAltNameExtension
     *             is thrown when Subject Alternative Name is not present in Entity Profile
     */
    protected Set<SubjectAltNameFieldType> getSubjectAltNameFieldTypes(final EntityProfileData entityProfileData) throws InvalidSubjectAltNameExtension {

        List<SubjectAltNameField> subjectAltNameFields = null;

        final Set<SubjectAltNameFieldType> subjectAltNameFieldTypes = new HashSet<SubjectAltNameFieldType>();
        final String subjectAltNameString = entityProfileData.getSubjectAltName();

        if (subjectAltNameString == null) {
            logger.error("Subject Alternative Name is not present in Entity Profile.");
            throw new InvalidSubjectAltNameExtension("Subject Alternative Name is not present in Entity Profile.");

        }
        subjectAltNameFields = JsonUtil.getObjectFromJson(SubjectAltName.class, subjectAltNameString).getSubjectAltNameFields();

        for (final SubjectAltNameField san : subjectAltNameFields) {
            subjectAltNameFieldTypes.add(san.getType());
        }

        return subjectAltNameFieldTypes;
    }

    /**
     * This method validates SubjectDN and fetches the subjectFieldTypes from subjectFields of entityProfileData.
     * 
     * @param entityProfileData
     *            which is fetched from database using entityfprofile name from CA Entity/Entity
     * 
     * @return Fields of Subject set in entity profile
     * 
     * @throws InvalidSubjectException
     *             thrown when given Subject is not present in Entity Profile.
     * 
     */
    protected Set<SubjectFieldType> getSubjectFieldTypes(final EntityProfileData entityProfileData) throws InvalidSubjectException {
        List<SubjectField> subjectFields = null;

        if (ValidationUtils.isNullOrEmpty(entityProfileData.getSubjectDN())) {
            logger.error("Subject is not present in Entity Profile.");
            throw new InvalidSubjectException("Subject is not present in Entity Profile.");
        }
        subjectFields = new Subject().fromASN1String(entityProfileData.getSubjectDN()).getSubjectFields();

        final Set<SubjectFieldType> subjectFieldTypes = new HashSet<SubjectFieldType>();

        for (final SubjectField subjectField : subjectFields) {
            subjectFieldTypes.add(subjectField.getType());
        }

        return subjectFieldTypes;
    }

    /**
     * This method checks whether the entityprofile in CA Entity/Entity has required and correct mandatory parameters
     * 
     * @param entityProfile
     *            is the entityprofile from CA Entity/Entity
     * @throws InvalidProfileException
     *             is thrown when profile type is not valid for CA Entity/Entity
     * @throws MissingMandatoryFieldException
     *             is thrown when a mandatory attribute is missing
     * 
     */
    protected void validateEntityProfile(final EntityProfile entityProfile, final boolean validateForCAEntity) throws EntityServiceException, InvalidProfileException, MissingMandatoryFieldException,
            ProfileNotFoundException {

        if (entityProfile == null) {
            logger.error("Entity Profile cannot be empty.");
            throw new MissingMandatoryFieldException("Entity Profile cannot be empty.");
        }

        if (entityProfile.getName() == null) {
            logger.error("Entity Profile cannot be empty.");
            throw new MissingMandatoryFieldException("Entity Profile name cannot be empty.");
        }

        final String entityProfileName = entityProfile.getName().trim();

        if (ValidationUtils.isNullOrEmpty(entityProfileName)) {
            logger.error("Entity Profile name cannot be null or empty.");
            throw new MissingMandatoryFieldException("Entity Profile name cannot be null or empty.");
        }

        final EntityProfileData entityProfileDataFromDB = getEntityProfileFromDB(entityProfileName);

        final boolean isCAProfile = entityProfileDataFromDB.getCertificateProfileData().isForCAEntity();

        if (!(validateForCAEntity == isCAProfile)) {
            final String errorMessage = (validateForCAEntity ? "Profile Type is not valid for CA entity" : "Profile Type is not valid for the given entity");

            logger.error(errorMessage);
            throw new InvalidProfileException(errorMessage);
        }
    }

    /**
     * 
     * This method verifies whether the given algorithm has mandatory fields(name) and compares algorithm present in CA Entity/Entity with the algorithm present in entityProfileData
     * 
     * @param algorithm
     *            Algorithm present in the entity
     * 
     * @param entityProfileData
     *            Name of the entity profile in entity
     * 
     * @throws AlgorithmNotFoundException
     *             Thrown when the given algorithm is not found.
     * 
     * @throws MissingMandatoryFieldException
     *             is thrown when a mandatory attribute is missing
     * 
     */
    protected void validateAlgorithm(final Algorithm algorithm, final EntityProfileData entityProfileData) throws AlgorithmNotFoundException, MissingMandatoryFieldException {
        if (algorithm.getName() == null) {
            logger.error("Key generation algorithm name cannot be empty");
            throw new MissingMandatoryFieldException("Key generation algorithm name cannot be empty");
        }

        if (algorithm.getName().trim().isEmpty()) {
            logger.error("Key generation algorithm cannot be empty");
            throw new MissingMandatoryFieldException("Key generation algorithm cannot be empty");
        }

        final boolean isAlgorithmValid = validateAlgorithmFromProfiles(algorithm, entityProfileData);

        if (!isAlgorithmValid) {
            logger.error("Key generation algorithm {} {}", algorithm.getName(), ProfileServiceErrorCodes.ERR_NOT_PRESENT_IN_PROFILES);
            throw new AlgorithmNotFoundException(algorithm.getName() + ProfileServiceErrorCodes.ERR_NOT_PRESENT_IN_PROFILES);
        }

    }

    /**
     * 
     * This method compares algorithm present in CA Entity/Entity with the algorithm present in entityProfileData
     * 
     * @param algorithm
     *            Algorithm present in the entity
     * 
     * @param entityProfileData
     *            Name of the entity profile in entity
     * 
     * @return boolean value result of comparision of two algorithms
     * 
     */
    private boolean validateAlgorithmFromProfiles(final Algorithm algorithm, final EntityProfileData entityProfileData) {

        final AlgorithmData entityProfileAlgorithmData = entityProfileData.getKeyGenerationAlgorithm();

        if (entityProfileAlgorithmData != null) {
            if (compareAlgorithmToData(algorithm, entityProfileAlgorithmData)) {
                return true;
            }
        }

        final Set<AlgorithmData> CertProfileAlgorithmDatas = entityProfileData.getCertificateProfileData().getKeyGenerationAlgorithms();
        if (CertProfileAlgorithmDatas != null) {
            for (final AlgorithmData algorithmData : CertProfileAlgorithmDatas) {
                if (compareAlgorithmToData(algorithm, algorithmData)) {
                    return true;
                }
            }
        }
        return false;

    }

    /**
     * This method compares two algorithms and returns the result of comparision
     * 
     * @param algorithm
     *            Algorithm present in the entity
     * @param algorithmData
     *            algorithmData present in entityProfileData
     * @return boolean value result of comparision of two algorithms
     */
    private boolean compareAlgorithmToData(final Algorithm algorithm, final AlgorithmData algorithmData) {
        final long algorithmKeySize = algorithm.getKeySize();
        final long algorithmDataKeySize = algorithmData.getKeySize();
        final String algorithmName = algorithm.getName().trim();
        final String algorithmDataName = algorithmData.getName().trim();

        if ((algorithmDataKeySize == algorithmKeySize) && (algorithmDataName.equalsIgnoreCase(algorithmName))) {
            return true;
        }
        return false;
    }

    /**
     * 
     * This method validates subjectAltName present in CA Entity/Entity certificateauthority data and validates subjectAltNameFieldTypes present in entityProfileData
     * 
     * @param subjectAltName
     *            Subject Alternative Name in entity
     * 
     * @param entityProfileData
     *            entityProfileData corresponding to entity profile in entity
     * 
     * @throws InvalidSubjectAltNameExtension
     *             is thrown when subjectAltNameFieldType is not present in Entity Profile
     */
    protected <T extends AbstractEntity> void validateSubjectAltName(final SubjectAltName subjectAltName, final EntityProfileData entityProfileData) throws InvalidSubjectAltNameExtension {
        logger.debug("Validating Subject ALternative Name:{} " , subjectAltName);

        final List<SubjectAltNameField> entitySAN = subjectAltName.getSubjectAltNameFields();

        if (ValidationUtils.isNullOrEmpty(entitySAN)) {
            return;
        }

        final Set<SubjectAltNameFieldType> subjectAltNameFieldTypesFromDB = getSubjectAltNameFieldTypes(entityProfileData);

        for (final SubjectAltNameField subjectAltNameField : entitySAN) {
            if (!subjectAltNameFieldTypesFromDB.contains(subjectAltNameField.getType())) {
                logger.error("unknown SubjectAltNameType::{}", subjectAltNameField.getType());
                throw new InvalidSubjectAltNameExtension(subjectAltNameField.getType() + " is not present in Entity Profile ");
            } else {
                subjectAltNameValidator.validate(subjectAltNameField);
            }
        }
    }

    /**
     * This method is used to validate Certificate Expiry Notification Details provided by user
     * 
     * @param certExpiryNotificationDetails
     *            Set<CertificateExpiryNotificationDetails> which is used to validate Certificate Expiry Notification Details provided by user
     * 
     * @throws InvalidEntityAttributeException
     */
    protected void validateCertificateExpiryNotificationDetails(final Set<CertificateExpiryNotificationDetails> certExpiryNotificationDetails) throws InvalidEntityAttributeException {
        logger.debug("Validating CertificateExpiryNotificationDetails for Entity");

        NotificationSeverity notificationSeverity = null;
        Duration periodBeforeExpiry;
        Duration frequencyOfNotification;
        int periodBeforeExpiryDays;
        int frequencyOfNotificationDays;
        final List<NotificationSeverity> notificationSeverityList = new ArrayList<NotificationSeverity>();

        for (CertificateExpiryNotificationDetails certExpiryNotificationDetail : certExpiryNotificationDetails) {
            notificationSeverity = certExpiryNotificationDetail.getNotificationSeverity();

            if (notificationSeverity == null) {
                logger.error(ErrorMessages.NOTIFICATION_SEVERITY_IS_MISSING);
                throw new InvalidEntityAttributeException(ErrorMessages.NOTIFICATION_SEVERITY_IS_MISSING);
            }

            if (notificationSeverityList.contains(notificationSeverity)) {
                logger.error(ErrorMessages.DUPLICATE_NOTIFICATION_SEVERITY);
                throw new InvalidEntityAttributeException(ErrorMessages.DUPLICATE_NOTIFICATION_SEVERITY);
            }
            notificationSeverityList.add(notificationSeverity);

            periodBeforeExpiry = certExpiryNotificationDetail.getPeriodBeforeExpiry();

            if (periodBeforeExpiry == null) {
                logger.error(ErrorMessages.PERIOD_BEFORE_EXPIRY_IS_MISSING);
                throw new InvalidEntityAttributeException(ErrorMessages.PERIOD_BEFORE_EXPIRY_IS_MISSING);
            }

            periodBeforeExpiryDays = periodBeforeExpiry.getDays();

            frequencyOfNotification = certExpiryNotificationDetail.getFrequencyOfNotification();

            if (frequencyOfNotification == null) {
                logger.error(ErrorMessages.FREQUENCY_OF_NOTIFICATION_IS_MISSING);
                throw new InvalidEntityAttributeException(ErrorMessages.FREQUENCY_OF_NOTIFICATION_IS_MISSING);
            }

            frequencyOfNotificationDays = frequencyOfNotification.getDays();

            switch (notificationSeverity.getId()) {

            case 1:
                if (periodBeforeExpiryDays >= 1 && periodBeforeExpiryDays <= 30) {
                    if (frequencyOfNotificationDays == 1) {
                        break;
                    }
                    logger.error(ErrorMessages.INVALID_FREQUENCY_OF_NOTIFICATION_FOR_CRITICAL);
                    throw new InvalidEntityAttributeException(ErrorMessages.INVALID_FREQUENCY_OF_NOTIFICATION_FOR_CRITICAL);

                } else {
                    logger.error(ErrorMessages.INVALID_PERIOD_BEFORE_EXPIRY_FOR_CRITICAL);
                    throw new InvalidEntityAttributeException(ErrorMessages.INVALID_PERIOD_BEFORE_EXPIRY_FOR_CRITICAL);
                }

            case 2:
                if (periodBeforeExpiryDays >= 31 && periodBeforeExpiryDays <= 60) {
                    if (frequencyOfNotificationDays > 0 && frequencyOfNotificationDays <= 2) {
                        break;
                    }
                    logger.error(ErrorMessages.INVALID_FREQUENCY_OF_NOTIFICATION_FOR_MAJOR);
                    throw new InvalidEntityAttributeException(ErrorMessages.INVALID_FREQUENCY_OF_NOTIFICATION_FOR_MAJOR);
                } else {
                    logger.error(ErrorMessages.INVALID_PERIOD_BEFORE_EXPIRY_FOR_MAJOR);
                    throw new InvalidEntityAttributeException(ErrorMessages.INVALID_PERIOD_BEFORE_EXPIRY_FOR_MAJOR);
                }

            case 3:
                if (periodBeforeExpiryDays >= 61 && periodBeforeExpiryDays <= 90) {
                    if (frequencyOfNotificationDays > 0 && frequencyOfNotificationDays <= 4) {
                        break;
                    }
                    logger.error(ErrorMessages.INVALID_FREQUENCY_OF_NOTIFICATION_FOR_WARNING);
                    throw new InvalidEntityAttributeException(ErrorMessages.INVALID_FREQUENCY_OF_NOTIFICATION_FOR_WARNING);
                } else {
                    logger.error(ErrorMessages.INVALID_PERIOD_BEFORE_EXPIRY_FOR_WARNING);
                    throw new InvalidEntityAttributeException(ErrorMessages.INVALID_PERIOD_BEFORE_EXPIRY_FOR_WARNING);
                }
            case 4:
                if (periodBeforeExpiryDays >= 91 && periodBeforeExpiryDays <= 180) {
                    if (frequencyOfNotificationDays > 0 && frequencyOfNotificationDays <= 7) {
                        break;
                    }
                    logger.error(ErrorMessages.INVALID_FREQUENCY_OF_NOTIFICATION_FOR_MINOR);
                    throw new InvalidEntityAttributeException(ErrorMessages.INVALID_FREQUENCY_OF_NOTIFICATION_FOR_MINOR);
                } else {
                    logger.error(ErrorMessages.INVALID_PERIOD_BEFORE_EXPIRY_FOR_MINOR);
                    throw new InvalidEntityAttributeException(ErrorMessages.INVALID_PERIOD_BEFORE_EXPIRY_FOR_MINOR);
                }
            default:
                logger.error(ErrorMessages.INVALID_NOTIFICATION_SEVERITY);
                throw new InvalidEntityAttributeException(ErrorMessages.INVALID_NOTIFICATION_SEVERITY);
            }

        }
        logger.debug("Completed Validating CertificateExpiryNotificationDetails for Entity ");
    }
}