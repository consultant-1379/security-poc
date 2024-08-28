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

import java.util.List;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import com.ericsson.oss.itpf.security.pki.common.model.CAStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CRLDistributionPoints;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.DistributionPoint;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.DistributionPointName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.ReasonFlag;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.CertificateExtensionsQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidCRLDistributionPointsExtension;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;

/**
 * This class validates CRLDistributionPoint extension. For this extension, critical must be false.
 * <p>
 * If given, reasonflag alone can't be specified, either DistributionPointName or CRLIssuer must be specified.
 * </p>
 * <p>
 * If DistributionPointName given, either list of fullnames or NameRelativeToCRLIssuer must be specified. List of full names must be valid ldap, http or ftp URLs.
 * </p>
 * <p>
 * If nameRelativeToCRLIssuer or CRLIssuer given, must be a valid CAEntity.
 * </p>
 *
 */
@CertificateExtensionsQualifier(CertificateExtensionType.CRL_DISTRIBUTION_POINTS)
public class CRLDistributionPointValidator extends StandardExtensionValidator {

    private final static String CA_NAME_PATH = "certificateAuthorityData.name";

    private static final String CDPS_IPV4_URL_PATTERN = "^(http|https|HTTP|HTTPS)://\\$FQDN_IPV4/(pki-cdps)?\\?ca_name=\\$CANAME&ca_cert_serialnumber=\\$CACERTSERIALNUMBER$";
    private static final String CDPS_IPV6_URL_PATTERN = "^(http|https|HTTP|HTTPS)://\\$FQDN_IPV6/(pki-cdps)?\\?ca_name=\\$CANAME&ca_cert_serialnumber=\\$CACERTSERIALNUMBER$";
    private static final String CDPS_DNS_URL_PATTERN = "^(http|https|HTTP|HTTPS)://\\$FQDN_DNS/(pki-cdps)?\\?ca_name=\\$CANAME&ca_cert_serialnumber=\\$CACERTSERIALNUMBER$";
    @Override
    public void validate(final CertificateExtension certificateExtension, final boolean isProfileForCAEntity, final String issuerName) throws ProfileServiceException,
    InvalidCRLDistributionPointsExtension, MissingMandatoryFieldException {

        validateCRLDistributionPointsExtension((CRLDistributionPoints) certificateExtension, issuerName);

    }

    /**
     * @param cRLDistributionPoints
     * @throws InternalServiceException
     */
    private void validateCRLDistributionPointsExtension(final CRLDistributionPoints cRLDistributionPoints, final String issuerName) throws ProfileServiceException,
    InvalidCRLDistributionPointsExtension, MissingMandatoryFieldException {

        if (isCertificateExtensionDefined(cRLDistributionPoints)) {
            validateCRLDistributionPoints(cRLDistributionPoints, issuerName);
        }
    }

    /**
     * @param cRLDistributionPoints
     * @throws InternalServiceException
     */
    private void validateCRLDistributionPoints(final CRLDistributionPoints cRLDistributionPoints, final String issuerName) throws ProfileServiceException, InvalidCRLDistributionPointsExtension,
    MissingMandatoryFieldException {
        logger.debug("Validating CRLDistributionPoints in Certificate Profile {}", cRLDistributionPoints);

        if (isCertificateExtensionCritical(cRLDistributionPoints)) {
            logger.error("For CRLDistributionPoint, critical must be false!");
            throw new InvalidCRLDistributionPointsExtension(ProfileServiceErrorCodes.CRL_DISTRIBUTION_POINT + ProfileServiceErrorCodes.CRITICAL_MUST_BE_FALSE);
        }

        validateListOfCRLDistributionPoints(cRLDistributionPoints.getDistributionPoints(), issuerName);
    }

    /**
     * @param crlDistributionPoints
     * @throws InternalServiceException
     */
    private void validateListOfCRLDistributionPoints(final List<DistributionPoint> cRLDistributionPoints, final String issuerName) throws ProfileServiceException,
    InvalidCRLDistributionPointsExtension, MissingMandatoryFieldException {

        if (ValidationUtils.isNullOrEmpty(cRLDistributionPoints)) {
            logger.error("If present, atleast one CRLDistributionPoint must be specified!");
            throw new MissingMandatoryFieldException(ProfileServiceErrorCodes.INVALID_CRL_DISTRIBUTION_POINTS);
        }

        for (final DistributionPoint cRLDistributionPoint : cRLDistributionPoints) {
            if (cRLDistributionPoint != null) {
                validateCRLDistributionPoint(cRLDistributionPoint, issuerName);
            }
        }

    }

    /**
     * @param distributionPointName
     * @param CRLIssuer
     */
    private void checkCRLDistributionPointParams(final DistributionPoint cRLDistributionPoint) throws ProfileServiceException, InvalidCRLDistributionPointsExtension {
        final ReasonFlag reasonFlag = cRLDistributionPoint.getReasonFlag();
        final DistributionPointName distributionPointName = cRLDistributionPoint.getDistributionPointName();
        final String cRLIssuer = cRLDistributionPoint.getCRLIssuer();

        if (reasonFlag != null) {
            if (distributionPointName == null && ValidationUtils.isNullOrEmpty(cRLIssuer)) {
                logger.error("If ReasonFlag present, either DistributionPointName or CRLIssuer must be specified!");
                throw new InvalidCRLDistributionPointsExtension(ProfileServiceErrorCodes.REASON_FLAG_PRESENT + ProfileServiceErrorCodes.INVALID_DISTRIBUTION_POINT);
            }
        }

        if (distributionPointName != null && cRLIssuer != null) {
            logger.error("Either DistributionPointName or CRLIssuer must be specified... both can't be present!");
            throw new InvalidCRLDistributionPointsExtension(ProfileServiceErrorCodes.INVALID_DISTRIBUTION_POINT);
        }
    }

    /**
     * @param cRLDistributionPoint
     * @param issuerName
     */
    private void checkCRLIssuerIsSameAsCertificateIssuer(final DistributionPoint cRLDistributionPoint, final String issuerName) throws ProfileServiceException, InvalidCRLDistributionPointsExtension {
        final DistributionPointName distributionPointName = cRLDistributionPoint.getDistributionPointName();
        final String cRLIssuer = cRLDistributionPoint.getCRLIssuer();

        if (isRootCA(issuerName) || isCertificateIssuerSameAsCRLIssuer(issuerName, cRLIssuer)) {
            if (!ValidationUtils.isNullOrEmpty(cRLIssuer)) {
                logger.error("If the certificate issuer is also the CRL issuer, then CRLIssuer field must be omitted and distributionPointName must be included!");
                throw new InvalidCRLDistributionPointsExtension(ProfileServiceErrorCodes.INVALID_DISTRIBUTION_POINT_FIELDS);
            }

            if (distributionPointName == null) {
                logger.error("If the certificate issuer is also the CRL issuer, then CRLIssuer field must be omitted and distributionPointName must be included!");
                throw new InvalidCRLDistributionPointsExtension(ProfileServiceErrorCodes.INVALID_DISTRIBUTION_POINT_FIELDS);
            }
        }
    }

    /**
     * @param issuerName
     * @param cRLIssuer
     * @return
     */
    private boolean isCertificateIssuerSameAsCRLIssuer(final String issuerName, final String cRLIssuer) {
        return issuerName.equals(cRLIssuer); // This is checked if
        // isRootCA(issuerName) condition
        // fails implying that it's either
        // subCA or End Entity
    }

    /**
     * @param issuerName
     * @return
     */
    private boolean isRootCA(final String issuerName) {
        return ValidationUtils.isNullOrEmpty(issuerName);
    }

    /**
     * @param cRLDistributionPoint
     * @throws InternalServiceException
     */
    private void validateCRLDistributionPoint(final DistributionPoint cRLDistributionPoint, final String issuerName) throws ProfileServiceException, InvalidCRLDistributionPointsExtension {
        logger.debug("Validating CRLDistributionPoint : {}", cRLDistributionPoint);
        final DistributionPointName distributionPointName = cRLDistributionPoint.getDistributionPointName();
        final String cRLIssuer = cRLDistributionPoint.getCRLIssuer();
        checkCRLDistributionPointParams(cRLDistributionPoint);
        checkCRLIssuerIsSameAsCertificateIssuer(cRLDistributionPoint, issuerName);

        if (distributionPointName != null) {
            validateCRLDistributionPointName(distributionPointName);
        }

        if (!ValidationUtils.isNullOrEmpty(cRLIssuer)) {
            validateCRLIssuer(cRLIssuer);
        }

    }

    /**
     * @param cRLDistributionPointName
     * @throws InternalServiceException
     */
    private void validateCRLDistributionPointName(final DistributionPointName cRLDistributionPointName) throws ProfileServiceException, InvalidCRLDistributionPointsExtension {
        logger.debug("Validating DistributionPointName{}", cRLDistributionPointName);

        final List<String> fullnames = cRLDistributionPointName.getFullName();
        final String cRLIssuer = cRLDistributionPointName.getNameRelativeToCRLIssuer();

        final boolean isFullNamesNotExists = ValidationUtils.isNullOrEmpty(fullnames);
        final boolean isCrlIssuerNotExists = ValidationUtils.isNullOrEmpty(cRLIssuer);

        if (isFullNamesNotExists && isCrlIssuerNotExists) {
            logger.error("Either list of fullnames or NameRelativeToCRLIssuer must be specified!");
            throw new InvalidCRLDistributionPointsExtension(ProfileServiceErrorCodes.INVALID_DISTRIBUTION_POINT_NAME);
        }

        if (!isFullNamesNotExists && !isCrlIssuerNotExists) {
            logger.error("Either list of fullnames or NameRelativeToCRLIssuer must be specified... both can't be present!");
            throw new InvalidCRLDistributionPointsExtension(ProfileServiceErrorCodes.INVALID_DISTRIBUTION_POINT_NAME);
        }

        if (!isFullNamesNotExists) {
            validateFullNames(fullnames);
        }

        if (!isCrlIssuerNotExists) {
            final String nameRelativeToCRLIssuer = cRLDistributionPointName.getNameRelativeToCRLIssuer();
            final boolean isGivenCRLIssuerValid = isValidCRLIssuer(nameRelativeToCRLIssuer);

            if (!isGivenCRLIssuerValid) {
                logger.error("Invalid NameRelativeToCRLIssuer given!");
                throw new InvalidCRLDistributionPointsExtension(ProfileServiceErrorCodes.INVALID_NAME_RELATIVE_TO_CRL_ISSUER);
            }

        }
    }

    /**
     * @param cRLIssuer
     * @throws InternalServiceException
     */
    private void validateCRLIssuer(final String cRLIssuer) throws ProfileServiceException, InvalidCRLDistributionPointsExtension {
        logger.debug("Validating CRLIssuer{}", cRLIssuer);

        final boolean isGivenCRLIssuerValid = isValidCRLIssuer(cRLIssuer);

        if (!isGivenCRLIssuerValid) {
            logger.error("Invalid CRLIssuer name given!");
            throw new InvalidCRLDistributionPointsExtension(ProfileServiceErrorCodes.INVALID_CRL_ISSUER);
        }
    }

    private boolean isValidCRLIssuer(final String cRLIssuerName) throws ProfileServiceException {
        final CAEntityData isValidCRLIssuer = getEntity(CAEntityData.class, cRLIssuerName, CA_NAME_PATH);

        if (isValidCRLIssuer == null) {
            return false;
        }

        final CAStatus cAStatus = CAStatus.getStatus(isValidCRLIssuer.getCertificateAuthorityData().getStatus());

        if (cAStatus == CAStatus.INACTIVE || cAStatus == CAStatus.DELETED) {
            return false;
        }

        return true;
    }

    /**
     * This method will validate the given distribution point names .
     *
     * @param fullNames
     *            is the list of the distribution point names
     * @throws InvalidCRLDistributionPointsExtension
     *             thrown when a CDPS URL failed to match the pattern.
     */
    private void validateFullNames(final List<String> fullNames) throws InvalidCRLDistributionPointsExtension {
        for (final String fullName : fullNames) {

            if (!validatePattern(CDPS_IPV4_URL_PATTERN, fullName) && !validatePattern(CDPS_IPV6_URL_PATTERN, fullName) && !validatePattern(CDPS_DNS_URL_PATTERN, fullName)) {
                logger.error("Invalid CRLIssuer name given! {}", fullName);
                throw new InvalidCRLDistributionPointsExtension("CDPS URL found in distribution point name is in wrong format!");
            }
        }
    }

    /**
     * Method for validating the String against pattern
     *
     * @param patternString
     *            Pattern that is to used for validation of String.
     * @param value
     *            String value that is to validated against pattern.
     * @return true or false
     */
    public boolean validatePattern(final String patternString, final String value) {

        final Pattern pattern = Pattern.compile(patternString, Pattern.CASE_INSENSITIVE);
        final Matcher matcher = pattern.matcher(value);

        return matcher.matches();
    }

}
