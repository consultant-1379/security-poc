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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.standard;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.CertificateExtensionValidator;

/**
 * This abstract class contains common methods that are used by all standard certificate extension validators.
 *
 * <p>
 * This class is extended by {@link BasicConstraintsValidator} / {@link CRLDistributionPointValidator}/{@link KeyIdentifierValidator}/ {@link KeyUsageValidator}
 * </p>
 *
 */

public abstract class StandardExtensionValidator implements CertificateExtensionValidator {

    @Inject
    Logger logger;

    @Inject
    PersistenceManager persistenceManager;

    /**
     * This method checks whether the certificate extension is defined for the profile or not
     *
     * @param certificateExtension
     *            certificate extension object
     * @return boolean true if defined or false if not defined
     */
    public boolean isCertificateExtensionDefined(final CertificateExtension certificateExtension) {
        if (certificateExtension == null) {
            return false;
        }
        return true;
    }

    /**
     * This method returns if the given certificate extension is marked as critical or not
     *
     * @param certificateExtension
     *            certificate extension object
     * @return boolean true if marked as critical or false if not marked as critical
     */
    public boolean isCertificateExtensionCritical(final CertificateExtension certificateExtension) {
        if (certificateExtension.isCritical()) {
            return true;
        }
        return false;
    }

    /**
     * This method returns {@link CAEntity} / {@link Entity} if entity with given name is available in database
     *
     * @param entityClass
     *            entity class object
     * @param name
     *            name of the entity
     * @return generic entity object
     * @throws InternalServiceException
     *             if any exception arises when fetching algorithms from database
     */
    public <T> T getEntity(final Class<T> entityClass, final String name, final String namePath) throws ProfileServiceException {
        T entity = null;

        try {
            entity = persistenceManager.findEntityByName(entityClass, name, namePath);
        } catch (final PersistenceException persistenceException) {
            logger.debug("Error occured in finding Entity by name ", persistenceException);
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_VALIDATING);
        }

        return entity;
    }
}
