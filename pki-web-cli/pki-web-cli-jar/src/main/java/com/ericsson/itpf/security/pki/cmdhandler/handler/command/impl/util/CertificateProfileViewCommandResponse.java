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
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util;

import java.util.List;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.itpf.security.pki.cmdhandler.api.command.PkiNameValueCommandResponse;
import com.ericsson.itpf.security.pki.cmdhandler.api.exception.PkiErrorCodes;
import com.ericsson.itpf.security.pki.cmdhandler.util.CertificateExtensionType;
import com.ericsson.itpf.security.pki.cmdhandler.util.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;

/**
 * 
 * This class will add the Certificate profiles information in PkiNameValueCommandResponse object.
 * 
 * @author tcschsa
 */
public class CertificateProfileViewCommandResponse {

    @Inject
    private Logger logger;

    @Inject
    CommandHandlerUtils commandHandlerUtils;

    private static final String CERTIFICATE_PROFILE_DATA = "Certificate Profile Data::";
    private static final String VERSION = "Version:";
    private static final String FOR_CA_ENTITY = "For CA Entity: ";
    private static final String IS_CA_ENTITY = "Is CA Entity: ";
    private static final String SIGNATURE_ALGORITHM = "Signature Algorithm: ";
    private static final String ISSUER_NAME = "Issuer Name:";
    private static final String ISSUER_UNIQUE_IDENTIFIER = "Issuer unique identifier: ";
    private static final String SKEW_CERTIFICATE_TIME = "Skew certificate time: ";
    private static final String SUBJECT_UNIQUE_IDENTIFIER = "Subject unique identifier: ";
    private static final String KEY_GENERATION_ALGORITHM = "Key Generation Algorithms: ";
    private static final String CERTIFICATE_EXTENSION = "Certificate Extensions: ";
    private static final String BASIC_CONSTRAINTS = "Basic Constraints: ";
    private static final String AUTHORITY_INFORMATION_ACCESS = "Authority Information Access: ";
    private static final String AUTHORITY_KEY_IDENTIFIER = "Authority Key Identifier:";
    private static final String SUBJECT_KEY_IDENTIFIER = "Subject Key Identifier: ";
    private static final String SUBJECT_ALT_NAME = "Subject Alt Name: ";
    private static final String KEY_USAGE = "Key Usage: ";
    private static final String EXTENDED_KEY_USAGE = "Extended Key Usage: ";
    private static final String CRL_DIST_POINTS = "CRL Distribution Points: ";
    private static final String IS_CRITICAL = " Is Critical: ";
    private static final String PATH_LEN_CONSTRAINT = " Path Length Constraint: ";

    /**
     * Method to build the command response for viewing the certificate profile data
     * 
     * @param certificateProfile
     * @return PkiNameValueCommandResponse
     * 
     */
    public PkiNameValueCommandResponse buildCommandResponseForCertificateProfile(final CertificateProfile certificateProfile) {

        final PkiNameValueCommandResponse commandResponse = new PkiNameValueCommandResponse();

        commandResponse.add(CERTIFICATE_PROFILE_DATA, Constants.EMPTY_STRING);
        commandResponse.add(Constants.NAME_VIEW, certificateProfile.getName());
        commandResponse.add(VERSION, (null != certificateProfile.getVersion() ? certificateProfile.getVersion().name() : Constants.EMPTY_STRING));
        commandResponse.add(Constants.IS_ACTIVE, ValidationUtils.isTrueOrFalse(certificateProfile.isActive()));
        commandResponse.add(Constants.MODIFIABLE_VIEW, ValidationUtils.isTrueOrFalse(certificateProfile.isModifiable()));
        commandResponse.add(Constants.PROFILE_VALIDITY, (null != certificateProfile.getProfileValidity()) ? commandHandlerUtils.getDateString(certificateProfile.getProfileValidity())
                : Constants.EMPTY_STRING);
        commandResponse.add(FOR_CA_ENTITY, ValidationUtils.isTrueOrFalse(certificateProfile.isForCAEntity()));
        commandResponse.add(SIGNATURE_ALGORITHM, (null != certificateProfile.getSignatureAlgorithm() ? certificateProfile.getSignatureAlgorithm().getName() : Constants.EMPTY_STRING));

        commandResponse.add(ISSUER_NAME, (null != certificateProfile.getIssuer() ? certificateProfile.getIssuer().getCertificateAuthority().getName() : Constants.EMPTY_STRING));
        commandResponse.add(Constants.SUBJECT, commandHandlerUtils.getAllSubjectFields(certificateProfile.getSubjectCapabilities()));
        commandResponse.add(ISSUER_UNIQUE_IDENTIFIER, ValidationUtils.isTrueOrFalse(certificateProfile.isIssuerUniqueIdentifier()));
        commandResponse.add(SKEW_CERTIFICATE_TIME, (null != certificateProfile.getSkewCertificateTime() ? certificateProfile.getSkewCertificateTime().toString() : Constants.EMPTY_STRING));

        commandResponse.add(SUBJECT_UNIQUE_IDENTIFIER, ValidationUtils.isTrueOrFalse(certificateProfile.isSubjectUniqueIdentifier()));

        commandResponse.add(KEY_GENERATION_ALGORITHM,
                (null != certificateProfile.getKeyGenerationAlgorithms() ? commandHandlerUtils.getKeyGenerationAlgorithmDetails(certificateProfile.getKeyGenerationAlgorithms())
                        : Constants.EMPTY_STRING));

        if (certificateProfile.getCertificateExtensions() != null) {
            addCertificateProfileExtensionsInfo(commandResponse, certificateProfile);

        } else {
            commandResponse.add(CERTIFICATE_EXTENSION, Constants.EMPTY_STRING);
        }
        return commandResponse;
    }

    private void addCertificateProfileExtensionsInfo(final PkiNameValueCommandResponse commandResponse, final CertificateProfile certificateProfile) {

        final CertificateExtensions certificateExtensions = certificateProfile.getCertificateExtensions();
        final List<CertificateExtension> certificateExtensionList = certificateExtensions.getCertificateExtensions();

        for (final CertificateExtension certificateExtension : certificateExtensionList) {
            if (certificateExtension != null) {

                final CertificateExtensionType certificateExtensionType = CertificateExtensionType.getCertificateExtensionType(certificateExtension.getClass().getSimpleName());

                switch (certificateExtensionType) {
                case BASIC_CONSTRAINTS:
                    final BasicConstraints basicConstraints = (BasicConstraints) certificateExtension;
                    commandResponse.add(BASIC_CONSTRAINTS, (null != basicConstraints ? getBasicConstraintDetails(basicConstraints) : Constants.EMPTY_STRING));
                    break;

                case AUTHORITY_INFORMATION_ACCESS:
                    final AuthorityInformationAccess authorityInformationAccess = (AuthorityInformationAccess) certificateExtension;
                    commandResponse.add(AUTHORITY_INFORMATION_ACCESS, (null != authorityInformationAccess ? getAuthorityInformationAccessDetails(authorityInformationAccess) : Constants.EMPTY_STRING));
                    break;

                case AUTHORITY_KEY_IDENTIFIER:
                    final AuthorityKeyIdentifier authorityKeyIdentifier = (AuthorityKeyIdentifier) certificateExtension;
                    commandResponse.add(AUTHORITY_KEY_IDENTIFIER, (null != authorityKeyIdentifier ? getAuthorityKeyIdentifierDetails(authorityKeyIdentifier) : Constants.EMPTY_STRING));
                    break;

                case SUBJECT_KEY_IDENTIFIER:
                    final SubjectKeyIdentifier subjectKeyIdentifier = (SubjectKeyIdentifier) certificateExtension;
                    commandResponse.add(SUBJECT_KEY_IDENTIFIER, (null != subjectKeyIdentifier ? subjectKeyIdentifier.toString() : Constants.EMPTY_STRING));
                    break;

                case SUBJECT_ALT_NAME:
                    final SubjectAltName subjectAltName = (SubjectAltName) certificateExtension;
                    commandResponse.add(SUBJECT_ALT_NAME, commandHandlerUtils.getAllSubjectAltNameFields(subjectAltName));
                    break;

                case KEY_USAGE:
                    final KeyUsage keyUsage = (KeyUsage) certificateExtension;
                    commandResponse.add(KEY_USAGE, (!ValidationUtils.isNullOrEmpty(keyUsage.getSupportedKeyUsageTypes()) ? getKeyUsageList(keyUsage) : Constants.EMPTY_STRING));
                    break;

                case EXTENDED_KEY_USAGE:
                    final ExtendedKeyUsage extendedKeyUsage = (ExtendedKeyUsage) certificateExtension;
                    commandResponse.add(EXTENDED_KEY_USAGE, (!ValidationUtils.isNullOrEmpty(extendedKeyUsage.getSupportedKeyPurposeIds()) ? getExtendedKeyUsageList(extendedKeyUsage)
                            : Constants.EMPTY_STRING));
                    break;

                case CRL_DISTRIBUTION_POINTS:
                    final CRLDistributionPoints crlDistributionPoints = (CRLDistributionPoints) certificateExtension;
                    commandResponse.add(CRL_DIST_POINTS, (null != crlDistributionPoints ? getcrlDistributionPointsDetails(crlDistributionPoints) : Constants.EMPTY_STRING));
                    break;

                default:
                    logger.error("There is no Certifificate extension present with {} Type", certificateExtensionType);
                    throw new IllegalArgumentException(PkiErrorCodes.UNEXPECTED_SYSTEM_ERROR);

                }

            }
        }

    }

    private String getcrlDistributionPointsDetails(final CRLDistributionPoints crlDistributionPoints) {
        final List<DistributionPoint> distributionPoints = crlDistributionPoints.getDistributionPoints();
        return CommandHandlerUtils.getFieldValues(distributionPoints, Constants.COMMA);
    }

    private String getAuthorityKeyIdentifierDetails(final AuthorityKeyIdentifier authorityKeyIdentifier) {

        final String authorityKeyIdentifierDetails = IS_CRITICAL + (authorityKeyIdentifier.isCritical() ? Constants.TRUE : Constants.FALSE) + Constants.COMMA + AUTHORITY_KEY_IDENTIFIER
                + Constants.TYPE + authorityKeyIdentifier.getType().getName();
        return authorityKeyIdentifierDetails;
    }

    private String getAuthorityInformationAccessDetails(final AuthorityInformationAccess authorityInformationAccess) {

        final List<AccessDescription> accessDescriptions = authorityInformationAccess.getAccessDescriptions();
        return CommandHandlerUtils.getFieldValues(accessDescriptions, Constants.COMMA);
    }

    private String getBasicConstraintDetails(final BasicConstraints basicConstraints) {

        final String basicConstraintsDetails = IS_CA_ENTITY + (basicConstraints.isCA() ? Constants.TRUE : Constants.FALSE) + Constants.COMMA + IS_CRITICAL
                + (basicConstraints.isCritical() ? Constants.TRUE : Constants.FALSE) + Constants.COMMA + PATH_LEN_CONSTRAINT + String.valueOf(basicConstraints.getPathLenConstraint());
        return basicConstraintsDetails;
    }

    private final String getKeyUsageList(final KeyUsage keyUsageExtension) {
        final List<KeyUsageType> keyUsageTypeList = keyUsageExtension.getSupportedKeyUsageTypes();
        return CommandHandlerUtils.getFieldValues(keyUsageTypeList, Constants.COMMA);
    }

    private String getExtendedKeyUsageList(final ExtendedKeyUsage extendedkeyUsageExtension) {
        final List<KeyPurposeId> keyPurposeIds = extendedkeyUsageExtension.getSupportedKeyPurposeIds();
        return CommandHandlerUtils.getFieldValues(keyPurposeIds, Constants.COMMA);
    }

}
