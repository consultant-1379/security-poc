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

import java.util.Iterator;
import java.util.List;

import com.ericsson.oss.itpf.sdkutils.rest.json.JsonUtil;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.CertificateExtensionsQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.profile.ProfileServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidBasicConstraintsExtension;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateProfileData;

/**
 * This class validates BasicConstraints extension provide as part of Certificate Profile create request
 *
 * <p>
 * For CA, Basic Constraints must be critical. If not, root CA, path length must be 1 less than its issuer path length. For end entity, path length must be 0.
 * </p>
 */
@CertificateExtensionsQualifier(CertificateExtensionType.BASIC_CONSTRAINTS)
public class BasicConstraintsValidator extends StandardExtensionValidator {

    private final static String CA_NAME_PATH = "certificateAuthorityData.name";

    @Override
    public void validate(final CertificateExtension certificateExtension, final boolean isProfileForCAEntity, final String issuerName) throws ProfileServiceException {

        validateBasicConstraints((BasicConstraints) certificateExtension, isProfileForCAEntity, issuerName);
    }

    private void validateBasicConstraints(final BasicConstraints basicConstraints, final boolean isProfileForCAEntity, final String issuerName) throws ProfileServiceException,
            InvalidBasicConstraintsExtension {
        logger.debug("Validating BasicConstraints in CertificateProfile{}", basicConstraints);

        boolean isCA = false;

        if (isProfileForCAEntity) {

            if (!basicConstraints.isCA()) {
                logger.error("For CA, isCA flag in basic constraints must be true!");
                throw new InvalidBasicConstraintsExtension(ProfileServiceErrorCodes.GIVEN_CA + ProfileServiceErrorCodes.INVALID_CA_FLAG);
            }

            if (!isCertificateExtensionCritical(basicConstraints)) {
                logger.error("For CA ,BasicConstraints extension, critical must be true!");
                throw new InvalidBasicConstraintsExtension(ProfileServiceErrorCodes.GIVEN_CA + ProfileServiceErrorCodes.BASIC_CONSTRAINTS + ProfileServiceErrorCodes.CRITICAL_MUST_BE_TRUE);
            }

            if (!ValidationUtils.isNullOrEmpty(issuerName)) {
                final CAEntityData cAEntityDataFromDB = getEntity(CAEntityData.class, issuerName, CA_NAME_PATH);

                validatePathLengthConstraintForCA(basicConstraints.getPathLenConstraint(), cAEntityDataFromDB);
            }

        }

        if (isCertificateExtensionDefined(basicConstraints) && !isProfileForCAEntity) {
            isCA = basicConstraints.isCA();

            if (isCA) {
                logger.error("For end entities, isCA flag must be false!");
                throw new InvalidBasicConstraintsExtension(ProfileServiceErrorCodes.GIVEN_END_ENTITY + ProfileServiceErrorCodes.INVALID_END_ENTITY_FLAG);
            }

            if (basicConstraints.getPathLenConstraint() != null && basicConstraints.getPathLenConstraint() != 0) {
                logger.error("For end entity, PathLengthConstraint must be 0!");
                throw new InvalidBasicConstraintsExtension(ProfileServiceErrorCodes.GIVEN_END_ENTITY + ProfileServiceErrorCodes.INVALID_END_ENTITY_PATHLENGTH);
            }
        }
    }

    private void validatePathLengthConstraintForCA(final Integer pathLength, final CAEntityData cAEntityDataFromDB) throws ProfileServiceException, InvalidBasicConstraintsExtension {

        final CertificateProfileData certificateProfileData = cAEntityDataFromDB.getEntityProfileData().getCertificateProfileData();
        final CertificateExtensions issuerCertificateExtensions = JsonUtil.getObjectFromJson(CertificateExtensions.class, certificateProfileData.getCertificateExtensionsJSONData());

        if (issuerCertificateExtensions != null) {
            final List<CertificateExtension> issuerCertificateExtensionList = issuerCertificateExtensions.getCertificateExtensions();

            final Integer issuerPathLength = getIssuerPathLength(issuerCertificateExtensionList);

            if (!ValidationUtils.isNullOrEmpty(issuerPathLength)) {

                if (ValidationUtils.isNullOrEmpty(pathLength) || (pathLength > issuerPathLength - 1)) {
                    logger.error("For CA, pathlength should be always less than Issuer Path Length:", issuerPathLength);
                    throw new InvalidBasicConstraintsExtension(ProfileServiceErrorCodes.GIVEN_CA + ProfileServiceErrorCodes.INVALID_CA_PATHLENGTH + "[0..." + (issuerPathLength-1) + "]");
                }
            }

        }
    }

    private Integer getIssuerPathLength(final List<CertificateExtension> issuerCertificateExtensionList) {
        Integer issuerPathLength = null;

        for (final Iterator<CertificateExtension> iterator = issuerCertificateExtensionList.iterator(); iterator.hasNext();) {
            final CertificateExtension issuerCertificateExtension = iterator.next();

            if (issuerCertificateExtension instanceof BasicConstraints) {
                final BasicConstraints issuerBasicConstraints = (BasicConstraints) issuerCertificateExtension;
                issuerPathLength = issuerBasicConstraints.getPathLenConstraint();
                break;
            }
        }

        return issuerPathLength;
    }

}
