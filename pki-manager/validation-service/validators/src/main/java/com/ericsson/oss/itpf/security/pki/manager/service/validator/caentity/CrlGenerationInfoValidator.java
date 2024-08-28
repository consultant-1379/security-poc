/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.service.validator.caentity;

import java.util.List;

import javax.inject.Inject;
import javax.xml.datatype.Duration;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.crl.CRLVersion;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.crl.extension.CrlExtensions;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.PKIBaseException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.AlgorithmException;
import com.ericsson.oss.itpf.security.pki.manager.exception.crl.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidAuthorityInformationAccessExtension;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidAuthorityKeyIdentifierExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.configuration.SignatureAlgorithmValidator;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.entity.CRLExtensionsValidator;

/**
 * This class validates the CrlGenerationInfo of CaEntity i.e {@link CAEntity}
 *
 * @author xtelsow
 */
public class CrlGenerationInfoValidator implements CommonValidator<CAEntity> {

    @Inject
    Logger logger;

    @Inject
    SignatureAlgorithmValidator signatureAlgorithmValidator;

    @Inject
    CRLExtensionsValidator crlExtensionsValidator;

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.pki.manager.service.validator.common.CommonValidator#validate(java.lang.Object)
     */
    @Override
    public <ValidationException extends PKIBaseException> void validate(final CAEntity caEntity) throws ValidationException {
        validateCrlGenerationInfo(caEntity);
    }

    /**
     * This Method validates the CrlGenerationInfo of CaEntity i.e {@link CAEntity}
     *
     * @param caEntity
     *
     */
    private void validateCrlGenerationInfo(final CAEntity caEntity) throws InvalidCRLGenerationInfoException, MissingMandatoryFieldException, UnsupportedCRLVersionException {
        logger.debug("Validating CrlGenerationInfo for CA Entity {}", caEntity.getCertificateAuthority().getName());

        if (caEntity.getCertificateAuthority().getCrlGenerationInfo() != null) {
            validateCrlGenerationInfo(caEntity.getCertificateAuthority().getCrlGenerationInfo());
        }

        logger.debug("Completed Validating CrlGenerationInfo for CA Entity {}", caEntity.getCertificateAuthority().getName());

    }

    /**
     * This method validates the CrlGenerationinfo mandatory attributes and validates the format of the data in each of the attributes.
     *
     * @param crlGenerationInfoList
     *            is the CrlGenerationInfo associated with a CertificateAuthority
     * @throws MissingMandatoryFieldException
     *             is thrown when a mandatory attribute is missing
     * @throws InvalidCRLGenerationInfoException
     *             thrown if the CRLGenerationInfo Fields are invalid
     */
    private void validateCrlGenerationInfo(final List<CrlGenerationInfo> crlGenerationInfoList) throws CRLExtensionException, InvalidAuthorityInformationAccessExtension,
            InvalidAuthorityKeyIdentifierExtension, InvalidCRLGenerationInfoException, InvalidIssuingDistributionPointExtension, UnsupportedCRLVersionException, MissingMandatoryFieldException {

        if (ValidationUtils.isNullOrEmpty(crlGenerationInfoList)) {
            logger.info("CRLGeneratoinInfo not provided for the CA");
            return;
        }

        for (final CrlGenerationInfo crlGenerationInfo : crlGenerationInfoList) {
            if (crlGenerationInfo.getVersion() == null) {
                logger.error("Invalid or Missing mandatory attribute CRLVersion in CRL GenerationInfo");
                throw new MissingMandatoryFieldException("Invalid or Missing mandatory attribute CRLVersion in CRL GenerationInfo.");
            }

            validateCrlExtensions(crlGenerationInfo.getCrlExtensions());

            if (crlGenerationInfo.getSignatureAlgorithm() == null) {
                logger.error("Missing mandatory attribute SignatureAlgorithm in CRL GenerationInfo");
                throw new MissingMandatoryFieldException(ProfileServiceErrorCodes.ERR_REQUIRED_ALGORITHM);
            }
                try {
                    logger.debug("Validating SignatureAlgorithm in CRLGenerationInfo");
                    signatureAlgorithmValidator.validate(crlGenerationInfo.getSignatureAlgorithm());
                } catch (final AlgorithmException algorithmException) {
                    logger.debug("Error occured while validing signature algorithm in CRL Generation Information ", algorithmException);
                    logger.error(algorithmException.getMessage());
                    throw new InvalidCRLGenerationInfoException(algorithmException.getMessage());
                }
            validateDurationFormat(crlGenerationInfo.getSkewCrlTime(), "SkewCrlTime");
            validateDurationFormat(crlGenerationInfo.getOverlapPeriod(), "CRL OverLapPeriod");
            validateValidtyPeriod(crlGenerationInfo.getValidityPeriod());
            validateCRLVersion(crlGenerationInfo.getVersion());
        }

    }

    /**
     * This method validates the CrlExtensions
     *
     * @param crlExtensions
     *            are the CRL extensions associated with a CrlGenerationInfo
     * @throws CRLExtensionException
     *             is thrown if the Invalid CRl Extension
     * @throws MissingMandatoryFieldException
     *             is thrown when a mandatory attribute is missing
     *
     */
    private void validateCrlExtensions(final CrlExtensions crlExtensions) throws CRLExtensionException, InvalidAuthorityKeyIdentifierExtension, InvalidAuthorityInformationAccessExtension,
            InvalidIssuingDistributionPointExtension, MissingMandatoryFieldException {
        try {
            if (crlExtensions != null) {
                crlExtensionsValidator.validateCRLExtension(CertificateExtensionType.AUTHORITY_KEY_IDENTIFIER, crlExtensions.getAuthorityKeyIdentifier());
                crlExtensionsValidator.validateCRLExtension(CertificateExtensionType.AUTHORITY_INFORMATION_ACCESS, crlExtensions.getAuthorityInformationAccess());
                crlExtensionsValidator.validateCRLNumberExtension(crlExtensions.getCrlNumber());
                crlExtensionsValidator.validateIssuingDistPointExtension(crlExtensions.getIssuingDistributionPoint());
            }
        } catch (final MissingMandatoryFieldException missingMandatoryFieldException) {
            logger.debug("Error occured due to Missing mandatory field in CRL GenerationIfno ", missingMandatoryFieldException);
            logger.error("Missing mandatory CRL Extension in CRL GenerationIfno." + missingMandatoryFieldException.getMessage());
            throw new MissingMandatoryFieldException("Missing mandatory CRL Extension in CRL GenerationIfno.");
        } catch (final InvalidAuthorityKeyIdentifierExtension invalidAuthorityKeyIdentifierExtension) {
            logger.debug("Error occured while validating authority KeyIdnetifier " , invalidAuthorityKeyIdentifierExtension);
            logger.error("Invalid authority KeyIdnetifier." + invalidAuthorityKeyIdentifierExtension.getMessage());
            throw new CRLExtensionException("Invalid authority KeyIdnetifier");
        } catch (final InvalidAuthorityInformationAccessExtension invalidAuthorityInformationAccessExtension) {
            logger.debug("Error occured while validating Authority Information Access ", invalidAuthorityInformationAccessExtension);
            logger.error("Invalid Authority Information Access." + invalidAuthorityInformationAccessExtension.getMessage());
            throw new CRLExtensionException("Invalid Authority Information Access");
        }
    }

    /**
     * This method validate the Duration format
     *
     * @param duration
     *            is the XML datatype duration
     * @param fieldType
     *            is the type of the duration we want to fetch
     * @throws InvalidCRLGenerationInfoException
     *             is thrown when a invalid value is set to the attribute duration
     */
    private void validateDurationFormat(final Duration duration, final String fieldType) throws InvalidCRLGenerationInfoException {
        logger.debug("Validating {} in CRLGenerationInfo {}", fieldType, duration);

        if (duration == null) {
            return;
        }

        if (!ValidationUtils.validateDurationFormat(duration)) {
            logger.debug("Invalid {} in CRLGenerationInfo", fieldType, duration);
            throw new InvalidCRLGenerationInfoException("Invalid CRLGenerationInfo attribute : CRLGenerationInfo." + fieldType);
        }

    }

    /**
     * This method validates the version of crlGenerationInfo
     *
     * @param cRLVersion
     *            the version of crlGenerationInfo
     * @throws UnsupportedCRLVersionException
     *             thrown if the given CRL version is not supported.
     */
    private void validateCRLVersion(final CRLVersion cRLVersion) throws UnsupportedCRLVersionException {
        if (!(cRLVersion == CRLVersion.V2)) {
            logger.error("Invalid CRL version. Only V2 is allowed!");
            throw new UnsupportedCRLVersionException("Invalid CRL version. Only V2 is allowed!");
        }
    }

    /**
     * This method validates the ValidityPeriod attribute of the CRLGenerationInfo of a CertificateAuthority
     *
     * @param validityPeriod
     *            is the validity period for a Crl
     * @throws MissingMandatoryFieldException
     *             is thrown when a mandatory attribute is missing
     */
    private void validateValidtyPeriod(final Duration validityPeriod) throws InvalidCRLGenerationInfoException, MissingMandatoryFieldException {
        if (validityPeriod == null) {
            logger.error("Missing validityPeriod for CRLGenerationInfo");
            throw new MissingMandatoryFieldException("Missing validityPeriod for CRLGenerationInfo");
        }

        validateDurationFormat(validityPeriod, "CRL ValidityPeriod");
    }
}
