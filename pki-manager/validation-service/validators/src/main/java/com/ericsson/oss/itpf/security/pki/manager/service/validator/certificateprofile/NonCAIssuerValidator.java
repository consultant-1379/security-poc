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

package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateprofile;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;

/**
 * This class validates Certificate Profile NonCAIssuer for a {@link CertificateProfile}
 */
public class NonCAIssuerValidator implements CommonValidator<CertificateProfile> {

    @Inject
    protected Logger logger;

    @Inject
    private PersistenceManager persistenceManager;

    protected final static String CA_NAME_PATH = "certificateAuthorityData.name";

    @Override
    public <ValidationException extends PKIBaseException> void validate(final CertificateProfile certificateProfile) throws ValidationException {
        validateIssuerName(certificateProfile.getIssuer());
    }

    private void validateIssuerName(final CAEntity issuer) throws CANotFoundException, InvalidCAException, MissingMandatoryFieldException, ProfileServiceException {

        if (issuer == null || ValidationUtils.isNullOrEmpty(issuer.getCertificateAuthority().getName())) {
            logger.error("Issuer name can't be null for empty {} ", issuer);
            throw new MissingMandatoryFieldException(ProfileServiceErrorCodes.ERR_INVALID_ISSUER_VALUE);
        }

        final String issuerName = issuer.getCertificateAuthority().getName();
        final CAEntityData caEntity = getEntity(CAEntityData.class, issuerName, CA_NAME_PATH);

        if (caEntity == null) {
            logger.error("Given issuer {}, not found! ", issuerName);
            throw new CANotFoundException(ProfileServiceErrorCodes.ERR_GIVEN_ISSUER + ProfileServiceErrorCodes.ERR_NOT_FOUND_OR_INACTIVE);
        }

        if (caEntity.isExternalCA()) {
            logger.error("CA Entity is an External CA, so External CA is not allowed to issue a certificate to the entity {} ", issuerName);
            throw new CANotFoundException(ProfileServiceErrorCodes.ERR_CA_ENTITY_IS_EXTERNAL);
        }

        final CAStatus cAStatus = CAStatus.getStatus(caEntity.getCertificateAuthorityData().getStatus());

        if (cAStatus == CAStatus.INACTIVE || cAStatus == CAStatus.DELETED) {
            logger.error("Issuer {} is in-active or soft-deleted! ", issuerName);
            throw new InvalidCAException(ProfileServiceErrorCodes.ERR_GIVEN_ISSUER + ProfileServiceErrorCodes.ERR_ISSUER_INACTIVE_SOFT_DELETED);
        }
    }

    private <T> T getEntity(final Class<T> entityClass, final String name, final String namePath) throws ProfileServiceException {
        T entity = null;

        try {
            entity = persistenceManager.findEntityByName(entityClass, name, namePath);
        } catch (final PersistenceException persistenceException) {
            logger.debug("Error when fetching entity " + name + " of " + entityClass, persistenceException);
            logger.error("Error when fetching entity " + name + " of " + entityClass);
            throw new ProfileServiceException(ProfileServiceErrorCodes.ERR_OCCURED_IN_VALIDATING);
        }

        return entity;
    }
}
