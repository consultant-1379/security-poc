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

import java.util.*;

import javax.persistence.PersistenceException;

import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.AlgorithmCategory;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ProfileServiceErrorCodes;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CertificateExtensionType;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.CertificateExtensionsQualifier;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.AlgorithmException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.MissingMandatoryFieldException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectKeyIdentifierExtension;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.AlgorithmData;

/**
 * This class validates SubjectKeyIdentifier extension.
 * <p>
 * SubjectKeyIdentifier extension must not be marked as critical
 * </p>
 * 
 */
@CertificateExtensionsQualifier(CertificateExtensionType.SUBJECT_KEY_IDENTIFIER)
public class SubjectKeyIdentifierValidator extends StandardExtensionValidator {

    private static final String ALGORITHM_NAME = "name";
    private static final String ALGORITHM_SUPPORTED = "supported";
    private static final String ALGORITHM_CATEGORIES = "categories";

    @Override
    public void validate(final CertificateExtension certificateExtension, final boolean isProfileForCAEntity, final String issuerName) throws AlgorithmException, AlgorithmNotFoundException,
            MissingMandatoryFieldException, InvalidSubjectKeyIdentifierExtension {

        validateSubjectKeyIdentifier((SubjectKeyIdentifier) certificateExtension);
    }

    /**
     * @param subjectKeyIdentifier
     */
    private void validateSubjectKeyIdentifier(final SubjectKeyIdentifier subjectKeyIdentifier) throws AlgorithmException, AlgorithmNotFoundException, MissingMandatoryFieldException,
            InvalidSubjectKeyIdentifierExtension {
        logger.debug("Validating SubjectKeyIdentifier in CertificateProfile{}", subjectKeyIdentifier);

        if (isCertificateExtensionDefined(subjectKeyIdentifier) && isCertificateExtensionCritical(subjectKeyIdentifier)) {
            logger.error("For SubjectKeyIdentifier extension, critical must be false!");
            throw new InvalidSubjectKeyIdentifierExtension(ProfileServiceErrorCodes.SUBJECT_KEY_IDENTIFIER + ProfileServiceErrorCodes.CRITICAL_MUST_BE_FALSE);
        }

        if (subjectKeyIdentifier.getKeyIdentifier() == null) {
            logger.error("In SubjectKeyIdentifier extension, KeyIdentifier cannot be null!");
            throw new MissingMandatoryFieldException(ProfileServiceErrorCodes.SUBJECT_KEY_IDENTIFIER + ProfileServiceErrorCodes.REQUIRED_KEY_IDENTIFIER);
        }

        final KeyIdentifier keyIdentifier = subjectKeyIdentifier.getKeyIdentifier();

        validateKeyIdentifier(keyIdentifier);
    }

    /**
     * @param keyIdentifier
     */
    private void validateKeyIdentifier(final KeyIdentifier keyIdentifier) throws AlgorithmException, AlgorithmNotFoundException, MissingMandatoryFieldException {
        if (keyIdentifier.getAlgorithm() == null) {
            logger.error("In KeyIdentifer of SubjectKeyIdentifier extension, algorithm must be specified!");
            throw new MissingMandatoryFieldException(ProfileServiceErrorCodes.KEY_IDENTIFIER + ProfileServiceErrorCodes.REQUIRED_KEY_IDENTIFIER_ALGORITHM);
        }

        final Algorithm keyIdentifierAlgorithm = keyIdentifier.getAlgorithm();
        final AlgorithmData algorithmDataFromDB = getAlgorithmDataFromDB(keyIdentifierAlgorithm);

        if (algorithmDataFromDB == null) {
            logger.error("Given algorithm not found or not supported or of invalid category{}", keyIdentifierAlgorithm.getName());
            throw new AlgorithmNotFoundException(ProfileServiceErrorCodes.GIVEN_KEY_IDENTIFIER_ALGORITHM + ProfileServiceErrorCodes.KEY_IDENTIFIER_ALGORITHM_NOT_FOUND_OR_SUPPORTED);

        }
    }

    private AlgorithmData getAlgorithmDataFromDB(final Algorithm algorithm) throws AlgorithmException {
        final Map<String, Object> input = new HashMap<String, Object>();

        final Set<Integer> categories = new HashSet<Integer>();
        categories.add(AlgorithmCategory.KEY_IDENTIFIER.getId());

        input.put(ALGORITHM_NAME, algorithm.getName());
        input.put(ALGORITHM_CATEGORIES, categories);
        input.put(ALGORITHM_SUPPORTED, Boolean.TRUE);

        AlgorithmData algorithmFromDB = null;

        try {
            algorithmFromDB = persistenceManager.findEntityWhere(AlgorithmData.class, input);
        } catch (final PersistenceException persistenceException) {
            logger.debug("Error when fetching algorithm with ", algorithm.getName(), " and  keysize ", algorithm.getKeySize(), persistenceException);
            logger.error("Error when fetching algorithm with ", algorithm.getName(), " and  keysize ", algorithm.getKeySize());
            throw new AlgorithmException(ProfileServiceErrorCodes.OCCURED_IN_VALIDATING);
        }

        return algorithmFromDB;
    }
}
