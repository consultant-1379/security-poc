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

import java.util.List;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.DistributionPointName;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CRLNumber;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.IssuingDistributionPoint;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.PersistenceManager;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidCRLNumberExtension;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.InvalidIssuingDistributionPointExtension;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.*;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.CertificateExtensionValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.certificateextensions.CertificateExtensionValidatorFactory;

/**
 * This class will call all the methods for validating CRL extensions
 * */
public class CRLExtensionsValidator {

    @Inject
    PersistenceManager persistenceManager;

    @Inject
    CertificateExtensionValidatorFactory certificateExtensionValidatorFactory;

    private final static String CA_NAME_PATH = "certificateAuthorityData.name";
    private static final String CDPS_URL_PATTERN = "^ldap://([a-z]*\\.[a-z]*\\.[a-z]*)?(:\\d{1,5})?\\/((dc=|cn=|ou=|o=|street=|l=|st=|c=|uid=)([a-z]+(\\%?(\\d)*?)?[a-z]*,?))+\\?([a-z]+,?;?)+[a-z()=?]*$|^(http:|https:|ftp:)//([a-z]*\\.[a-z]*\\.[a-z]*)\\/([a-z]*\\/)*(([a-z0-9]+\\.)+crl)$";

    /**
     * This method is used to validate the CRL Extensions
     *
     * @param certificateExtensionType
     *            is the type of certificate/crl extension
     * @param certificateExtension
     *            is the actual extension
     * @throws MissingMandatoryFieldException
     *
     * @throws InvalidAuthorityKeyIdentifierExtension
     *
     * @throws InvalidAuthorityInformationAccessExtension
     *
     **/
    public void validateCRLExtension(final CertificateExtensionType certificateExtensionType, final CertificateExtension certificateExtension) throws MissingMandatoryFieldException,
            InvalidAuthorityKeyIdentifierExtension, InvalidAuthorityInformationAccessExtension {
        if (certificateExtension != null) {
            final CertificateExtensionValidator certificateExtensionValidator = certificateExtensionValidatorFactory.getCertificateExtensionValidator(certificateExtensionType);
            certificateExtensionValidator.validate(certificateExtension, false, null);
        }
    }

    /**
     * This method is used to validate the CRL Number Extension
     *
     * @param crlNumber
     *            is the crlNumber extension
     * @throws InvalidCRLNumberExtension
     *
     **/
    public void validateCRLNumberExtension(final CRLNumber crlNumber) throws InvalidCRLNumberExtension {

        if (crlNumber == null || (crlNumber.getSerialNumber() != null || crlNumber.isCritical())) {
            throw new InvalidCRLNumberExtension("CRLNumber extension should be non-critical");
        }
    }

    /**
     * This method is used to validate the CRL IssuingDistributionPoint Extension
     *
     * @param idpDistributionPoint
     *            is the IssuingDistributionPoint extension
     * @throws InvalidIssuingDistributionPointExtension
     *
     **/
    public void validateIssuingDistPointExtension(final IssuingDistributionPoint idpDistributionPoint) throws InvalidIssuingDistributionPointExtension {

        if (idpDistributionPoint != null) {
            if (!idpDistributionPoint.isCritical()) {
                throw new InvalidIssuingDistributionPointExtension("Issuing Distribution Point Extension should be critical");
            }

            if ((idpDistributionPoint.isOnlyContainsUserCerts() && (idpDistributionPoint.isOnlyContainsCACerts() || idpDistributionPoint.isOnlyContainsAttributeCerts()))
                    || (idpDistributionPoint.isOnlyContainsCACerts() && (idpDistributionPoint.isOnlyContainsUserCerts() || idpDistributionPoint.isOnlyContainsAttributeCerts()))
                    || (idpDistributionPoint.isOnlyContainsAttributeCerts() && (idpDistributionPoint.isOnlyContainsUserCerts() || idpDistributionPoint.isOnlyContainsCACerts()))) {
                throw new InvalidIssuingDistributionPointExtension("In Issuing Distribution point only one which is CA certs, UserCerts or atrribute certs field is set to be true");
            }
            validateDistributionPointName(idpDistributionPoint.getDistributionPoint());
        }
    }

    private void validateDistributionPointName(final DistributionPointName distributionPointName) throws ProfileServiceException, InvalidCRLDistributionPointsExtension {

        final List<String> fullnames = distributionPointName.getFullName();
        final String cRLIssuer = distributionPointName.getNameRelativeToCRLIssuer();

        final boolean isFullNamesNotExists = ValidationUtils.isNullOrEmpty(fullnames);
        final boolean isCrlIssuerNotExists = ValidationUtils.isNullOrEmpty(cRLIssuer);

        if (isFullNamesNotExists && isCrlIssuerNotExists) {
            throw new InvalidCRLDistributionPointsExtension(ProfileServiceErrorCodes.INVALID_DISTRIBUTION_POINT_NAME);
        }

        if (!isFullNamesNotExists && !isCrlIssuerNotExists) {
            throw new InvalidCRLDistributionPointsExtension(ProfileServiceErrorCodes.INVALID_DISTRIBUTION_POINT_NAME);
        }

        if (!isFullNamesNotExists) {
            validateFullNames(fullnames);
        }

        if (!isCrlIssuerNotExists) {
            final String nameRelativeToCRLIssuer = distributionPointName.getNameRelativeToCRLIssuer();
            final boolean isGivenCRLIssuerValid = isValidCRLIssuer(nameRelativeToCRLIssuer);

            if (!isGivenCRLIssuerValid) {
                throw new InvalidCRLDistributionPointsExtension(ProfileServiceErrorCodes.INVALID_NAME_RELATIVE_TO_CRL_ISSUER);
            }

        }
    }

    /**
     * @param fullnames
     */
    private void validateFullNames(final List<String> fullnames) throws ProfileServiceException, InvalidCRLDistributionPointsExtension {

        for (final String fullname : fullnames) {
            if (!ValidationUtils.validatePattern(CDPS_URL_PATTERN, fullname)) {
                throw new InvalidCRLDistributionPointsExtension(ProfileServiceErrorCodes.INVALID_DISTRIBUTION_POINT_URL);
            }

        }

    }

    private boolean isValidCRLIssuer(final String cRLIssuerName) throws ProfileServiceException {
        final CAEntityData isValidCRLIssuer = getEntity(CAEntityData.class, cRLIssuerName, CA_NAME_PATH);

        if (isValidCRLIssuer == null) {
            return false;
        }

        final CAStatus cAStatus = CAStatus.getStatus(isValidCRLIssuer.getCertificateAuthorityData().getStatus());

        if (cAStatus == CAStatus.DELETED) {
            return false;
        }
        return true;
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
            throw new ProfileServiceException(ProfileServiceErrorCodes.OCCURED_IN_VALIDATING, persistenceException);
        }

        return entity;
    }
}
