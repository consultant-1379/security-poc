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
package com.ericsson.oss.itpf.security.pki.core.entitymanagement.validators;

import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameField;
import com.ericsson.oss.itpf.security.pki.core.common.constants.EntityManagementErrorCodes;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.EntityInfoData;
import com.ericsson.oss.itpf.security.pki.core.common.utils.OperationType;
import com.ericsson.oss.itpf.security.pki.core.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;

public class EntityValidator extends AbstractEntityValidator {

    @Inject
    Logger logger;

    @Inject
    SubjectAltNameValidator subjectAltNameValidator;

    @Inject
    SubjectValidator subjectValidator;

    private final static String NAME_PATH = "name";

    protected static final String OVERRIDING_OPERATOR = "?";

    /**
     * This method validates the input entity i.e, {@link EntityInfo} based on {@link OperationType}
     * 
     * @param entityInfo
     *            {@link EntityInfo} object to be validated.
     * @param operationType
     *            type of operation that specifies validations to be done for {@link EntityInfo} object.
     * @throws CoreEntityAlreadyExistsException
     *             thrown when trying to create an entity that already exists.
     * @throws CoreEntityServiceException
     *             thrown for any entity related database errors in PKI Core.
     */
    public void validateEntity(final EntityInfo entityInfo, final OperationType operationType) throws CoreEntityAlreadyExistsException, CoreEntityServiceException {

        logger.debug("Validating create EntityInfo {}", entityInfo);

        validateForInvalidObjects(entityInfo);

        final String trimmedName = entityInfo.getName().trim();
        entityInfo.setName(trimmedName);

        validateEntityName(entityInfo, operationType);

        validateNullOrEmptySubjectAndSAN(entityInfo.getSubject(), entityInfo.getSubjectAltName());

        logger.debug("Completed validating create Entity");
    }

    private void validateEntityName(final EntityInfo entityInfo, final OperationType operationType) throws CoreEntityAlreadyExistsException, CoreEntityServiceException {

        checkEntityNameFormat(entityInfo.getName());

        if (operationType.equals(OperationType.CREATE)) {
            checkNameAvailability(entityInfo.getName(), EntityInfoData.class, NAME_PATH);
        } else {
            final EntityInfoData entityInfoData = persistenceManager.findEntity(EntityInfoData.class, entityInfo.getId());
            checkNameForUpdate(entityInfo.getName(), entityInfoData.getName(), EntityInfoData.class, NAME_PATH);
        }
    }

    private void validateNullOrEmptySubjectAndSAN(final Subject subject, final SubjectAltName subjectAltName) {

        if (!isSubjectValid(subject) && !isSANValid(subjectAltName)) {
            logger.debug("Subject or Subject Alternative Name is mandatory.");
            throw new IllegalArgumentException("Subject or Subject Alternative Name is mandatory.");
        }

        if (subject != null) {
            validateEntitySubject(subject);
        }

        if (subjectAltName != null) {
            validateEntitySubjectAltName(subjectAltName);
        }
    }

    private void validateEntitySubject(final Subject subject) throws CoreEntityServiceException {
        logger.debug("Validating Subject {}" , subject);

        final List<SubjectField> subjectFieldList = subject.getSubjectFields();

        if (subjectFieldList == null || subjectFieldList.isEmpty()) {
            return;
        }

        for (final SubjectField subjectField : subjectFieldList) {

            final String subjectFieldValue = subjectField.getValue().trim();

            if (subjectFieldValue.equals(OVERRIDING_OPERATOR)) {
                continue;
            } else {
                subjectValidator.validateSubjectValue(subjectField.getType(), subjectFieldValue);
            }
        }
    }

    private void validateEntitySubjectAltName(final SubjectAltName subjectAltName) {
        logger.debug("Validating Subject ALternative Name {}" , subjectAltName);

        final List<SubjectAltNameField> subjectAltNameFieldList = subjectAltName.getSubjectAltNameFields();

        for (final SubjectAltNameField subjectAltNameField : subjectAltNameFieldList) {

            subjectAltNameValidator.validate(subjectAltNameField);

        }
    }

    private boolean isSubjectValid(final Subject subject) {
        if (subject == null) {
            return false;
        }

        final List<SubjectField> subjectFieldList = subject.getSubjectFields();

        if (ValidationUtils.isNullOrEmpty(subjectFieldList)) {
            return false;
        }

        for (final SubjectField subjectField : subjectFieldList) {
            if (subjectField == null || subjectField.getType() == null || ValidationUtils.isNullOrEmpty(subjectField.getValue())) {
                return false;
            }
        }
        return true;

    }

    private boolean isSANValid(final SubjectAltName subjectAltName) {
        if (subjectAltName == null) {
            return false;
        }

        final List<SubjectAltNameField> subjectAltNameFieldList = subjectAltName.getSubjectAltNameFields();

        if (ValidationUtils.isNullOrEmpty(subjectAltNameFieldList)) {
            return false;
        }

        for (final SubjectAltNameField subjectAltNameField : subjectAltNameFieldList) {

            if (subjectAltNameField == null || subjectAltNameField.getType() == null || subjectAltNameField.getValue() == null) {
                return false;
            }
        }

        return true;
    }

    /**
     * Check weather Entity can be Deleted or not with given {@link EntityStatus}
     * 
     * @param entityStatus
     *            {@link EntityStatus}
     * @return true/exception
     * @throws CoreEntityInUseException
     */
    public boolean checkEntityCanBeDeleted(final EntityStatus entityStatus) throws CoreEntityInUseException {

        if (entityStatus == EntityStatus.DELETED) {
            logger.info(EntityManagementErrorCodes.ENTITY_IS_DELETED);
        } else if (entityStatus == EntityStatus.ACTIVE) {
            logger.error(EntityManagementErrorCodes.ENTITY_IS_ACTIVE);
            throw new CoreEntityInUseException(EntityManagementErrorCodes.ENTITY_IS_ACTIVE);
        } else if (entityStatus == EntityStatus.REISSUE) {
            logger.error(EntityManagementErrorCodes.ENTITY_IS_REISSUED);
            throw new CoreEntityInUseException(EntityManagementErrorCodes.ENTITY_IS_REISSUED);
        }

        return true;
    }

    /**
     * @param entityInfo
     */
    private void validateForInvalidObjects(final EntityInfo entityInfo) {

        if (entityInfo == null) {
            throw new IllegalArgumentException(EntityManagementErrorCodes.ENTITY_ISNOTNULL);
        }
        if (entityInfo.getName() == null) {
            throw new IllegalArgumentException(EntityManagementErrorCodes.NAME_ISNOTNULL);
        }
        if (entityInfo.getName().trim().isEmpty()) {
            throw new IllegalArgumentException(EntityManagementErrorCodes.NAME_ISNOTEMPTY);
        }
    }

}
