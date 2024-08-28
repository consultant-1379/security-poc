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

import javax.inject.Inject;
import javax.persistence.EntityNotFoundException;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.core.common.constants.EntityManagementErrorCodes;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityAlreadyExistsException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException;

public abstract class AbstractEntityValidator {

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    private SystemRecorder systemRecorder;

    private static final String NAME_REGEX = "^[a-zA-Z0-9_.-]{3,255}$";

    /**
     * Method for verifying the entity name format
     * 
     * @param entityName
     *            name to be checked
     */
    public void checkEntityNameFormat(final String entityName) {
        if (!ValidationUtils.validatePattern(NAME_REGEX, entityName)) {
            logger.debug(EntityManagementErrorCodes.INVALID_NAME_FORMAT + "{} ", entityName);
            throw new IllegalArgumentException(EntityManagementErrorCodes.INVALID_NAME_FORMAT + " " + entityName);
        }
    }

    /**
     * Method for checking if string is null or empty
     * 
     * @param str
     *            String value that is checked for empty or null
     * @return true or false
     */
    public static boolean isNullOrEmpty(final String str) {
        if (str == null || str.trim().length() == 0) {
            return true;
        }

        return false;
    }

    /**
     * Method for checking if String is having ?
     * 
     * @param str
     *            String is having single ? symbol
     * @return true or false
     */
    public static boolean isValidSubjectString(final String str) {
        if ((str.length() == 1) && (str.compareTo("?") == 0)) {
            return true;
        }

        return false;
    }

    /**
     * Method for checking if given character is valid ASCII printable character
     * 
     * @param ch
     *            Character value that is checked whether ASCII printable or not
     * @return true or false
     */
    public static boolean isAsciiPrintable(final char ch) {
        return ch >= 0x0020 && ch < 0x007f;
    }

    /**
     * Method for checking if given String is valid ASCII printable
     * 
     * @param str
     *            String value that is checked whether ASCII printable or not
     * @return true or false
     */
    public static boolean isAsciiPrintable(final String str) {
        for (int i = str.length() - 1; i >= 0; i--) {
            final char ch = str.charAt(i);

            if (!isAsciiPrintable(ch)) {
                return false;
            }
        }

        return true;
    }

    /**
     * Method for checking the availability of entity name
     * 
     * @param entityName
     *            name to be checked
     * @param entity
     *            Class of {@link CertificateAuthorityData}/ {@link EntityData}
     * @param namePath
     * 
     * @throws CoreEntityAlreadyExistsException
     *             thrown when trying to create an entity that already exists.
     * @throws CoreEntityServiceException
     *             thrown when any internal Database errors or service exception occur.
     */
    public <T> void checkNameAvailability(final String entityName, final Class<T> entity, final String namePath) throws CoreEntityAlreadyExistsException, CoreEntityServiceException {

        try {
            if (!(persistenceManager.findEntityByName(entity, entityName, namePath) == null)) {
                logger.error("Entity with name {} already exists", entityName);
                systemRecorder.recordError("PKICore.EntityManagement", ErrorSeverity.ERROR, "Check name availability for entity " + entityName,
                        "PKI_CORE.ENTITY_VALIDATION", "Entity with name " + entityName + " already exists");
                throw new CoreEntityAlreadyExistsException("Entity with name " + entityName + " already exists");
            }
        } catch (PersistenceException persistenceException) {
            logger.debug("Error while checking database if name {} exists.", entityName);
            throw new CoreEntityServiceException("Error while checking database if name " + entityName + " exists ", persistenceException);
        }
    }

    /**
     * Method for retrieving the entity data from database
     * 
     * @param id
     * 
     * @param entity
     *            Class of {@link CertificateAuthorityData}/ {@link EntityData}
     * 
     * @return generic entity object which contains the data related to CertificateAuthorityData/EntityData
     * 
     * @throws EntityNotFoundException
     *             thrown when no entity exists with given id/name and entity profile name.
     */
    public <T> T getEntityDataById(final long id, final Class<T> entity) throws EntityNotFoundException {

        final T entityData = persistenceManager.findEntity(entity, id);

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
     * @param entity
     *            Class of {@link CertificateAuthorityData}/ {@link EntityInfo}
     * @param namePath
     * 
     * @throws CoreEntityAlreadyExistsException
     *             thrown when trying to create an entity that already exists.
     * @throws CoreEntityServiceException
     */
    public <T> void checkNameForUpdate(final String givenName, final String actualName, final Class<T> entity, final String namePath) throws CoreEntityAlreadyExistsException,
            CoreEntityServiceException {

        if (!actualName.equalsIgnoreCase(givenName)) {
            checkNameAvailability(givenName, entity, namePath);
        }
    }
}
