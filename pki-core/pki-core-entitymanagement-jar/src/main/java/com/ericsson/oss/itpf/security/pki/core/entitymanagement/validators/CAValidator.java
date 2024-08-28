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

import java.util.ArrayList;
import java.util.List;

import javax.inject.Inject;
import javax.persistence.PersistenceException;
import javax.xml.datatype.Duration;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameField;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;
import com.ericsson.oss.itpf.security.pki.core.common.constants.EntityManagementErrorCodes;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.AlgorithmPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CAEntityPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.common.utils.OperationType;
import com.ericsson.oss.itpf.security.pki.core.common.utils.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.*;

public class CAValidator extends AbstractEntityValidator {

    @Inject
    Logger logger;

    @Inject
    SubjectValidator subjectValidator;

    @Inject
    SubjectAltNameValidator subjectAltNameValidator;

    @Inject
    CAEntityPersistenceHandler cAEntityPersistenceHandler;

    @Inject
    AlgorithmPersistenceHandler algorithmPersistenceHandler;

    private final static String NAME_PATH = "name";

    protected static final String OVERRIDING_OPERATOR = "?";

    /**
     * Validate a {@link CertificateAuthority} in create operation.
     * 
     * @param certificateAuthority
     *            Instance of {@link CertificateAuthority} to be validated.
     * @throws CoreEntityAlreadyExistsException
     * 
     * @throws CoreEntityServiceException
     *             thrown for any entity related database errors in PKI Core.
     */
    public void validateCreate(final CertificateAuthority certificateAuthority) throws CoreEntityAlreadyExistsException, CoreEntityServiceException {

        validateCAEntity(certificateAuthority, OperationType.CREATE);
    }

    /**
     * Validate a {@link CertificateAuthority} in update operation.
     * 
     * @param certificateAuthority
     *            Instance of {@link CertificateAuthority} to be validated.
     * @throws CoreEntityAlreadyExistsException
     * 
     * @throws CoreEntityNotFoundException
     *             thrown when no entity exists with given id.
     * @throws CoreEntityServiceException
     *             thrown for any entity related database errors in PKI Core.
     */
    public void validateUpdate(final CertificateAuthority certificateAuthority) throws CoreEntityAlreadyExistsException, CoreEntityNotFoundException, CoreEntityServiceException {

        final long id = certificateAuthority.getId();

        try {
            final CertificateAuthorityData certificateAuthorityData = persistenceManager.findEntity(CertificateAuthorityData.class, id);

            if (certificateAuthorityData == null) {
                throw new CoreEntityNotFoundException("Certificate Authroity " + EntityManagementErrorCodes.NOT_FOUND_WITH_ID + id);
            }

        } catch (PersistenceException persistenceexception) {
            logger.error("Error in retrieving EntityInfo {}", persistenceexception.getMessage());
            throw new CoreEntityServiceException(ErrorMessages.ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE, persistenceexception);
        }

        validateCAEntity(certificateAuthority, OperationType.UPDATE);
    }

    /**
     * This method validates the input entity i.e, {@link CertificateAuthority} based on {@link OperationType}
     * 
     * @param certificateAuthority
     *            {@link CertificateAuthority} object to be validated.
     * @param operationType
     *            type of operation that specifies validations to be done for {@link CertificateAuthority} object.
     * @throws CoreEntityAlreadyExistsException
     * @throws CoreEntityNotFoundException
     *             thrown when no entity exists with given id/name and entity profile name.
     * @throws CoreEntityServiceException
     *             thrown for any entity related database errors in PKI Core.
     */
    public void validateCAEntity(final CertificateAuthority certificateAuthority, final OperationType operationType) throws CoreEntityAlreadyExistsException, CoreEntityServiceException {
        final String operation_type = operationType.toString().toLowerCase();
        logger.debug("Validating {} Certificate Authroity {}", operation_type, certificateAuthority);

        validateForInvalidObjects(certificateAuthority);

        final String trimmedName = certificateAuthority.getName().trim();
        certificateAuthority.setName(trimmedName);

        validateCAEntityName(certificateAuthority, operationType);

        if (certificateAuthority.getSubject() == null && certificateAuthority.getSubjectAltName() == null) {
            logger.debug("Subject or Subject Alternative Name is mandatory");
            throw new IllegalArgumentException("Subject or Subject Alternative Name is mandatory");
        }

        validateEntitySubject(certificateAuthority.getSubject());

        if (certificateAuthority.getSubjectAltName() != null) {
            validateEntitySubjectAltName(certificateAuthority.getSubjectAltName());
        }

        validateCrlGenerationInfo(certificateAuthority.getCrlGenerationInfo());

        logger.debug("Completed validating {} Certificate Authroity ", operation_type);
    }

    private void validateCAEntityName(final CertificateAuthority certificateAuthority, final OperationType operationType) throws CoreEntityAlreadyExistsException, CoreEntityServiceException {

        checkEntityNameFormat(certificateAuthority.getName());

        try {
            if (operationType == OperationType.CREATE) {
                checkNameAvailability(certificateAuthority.getName(), CertificateAuthorityData.class, NAME_PATH);
            } else if (operationType == OperationType.UPDATE) {
                final CertificateAuthorityData certificateAuthorityDataDB = persistenceManager.findEntity(CertificateAuthorityData.class, certificateAuthority.getId());
                checkNameForUpdate(certificateAuthority.getName(), certificateAuthorityDataDB.getName(), CertificateAuthorityData.class, NAME_PATH);
            }

        } catch (PersistenceException persistenceexception) {
            logger.error("Error in retrieving EntityInfo {}", persistenceexception.getMessage());
            throw new CoreEntityServiceException(ErrorMessages.ERROR_OCCURED_IN_RETREIVING_FROM_DATABASE, persistenceexception);
        }
    }

    private void validateEntitySubject(final Subject subject) {
        logger.debug("Validating Subject {}" , subject);

        if (subject == null) {
            throw new IllegalArgumentException("Subject cannot be null in CA Entity.");
        }

        final List<SubjectField> subjectFieldList = subject.getSubjectFields();

        if (subjectFieldList == null || subjectFieldList.isEmpty()) {
            throw new IllegalArgumentException("Subject cannot be null or empty in CA Entity.");
        }

        for (final SubjectField subjectField : subjectFieldList) {

            final String subjectFieldValue = subjectField.getValue();
            if (subjectFieldValue.equals(OVERRIDING_OPERATOR)) {
                logger.error("Overriding operator is not allowed in CA Entity for Subject Field::", subjectField);
                throw new IllegalArgumentException("Overriding operator is not allowed in CA Entity for Subject Field:" + subjectField);
            } else if (subjectFieldValue.isEmpty()) {
                logger.error(" Subject Field {} is empty.", subjectField);
                throw new IllegalArgumentException(subjectField + " is empty in Subject.");
            } else {
                subjectValidator.validateSubjectValue(subjectField.getType(), subjectFieldValue);
            }
        }
    }

    private void validateEntitySubjectAltName(final SubjectAltName subjectAltName) {
        logger.debug("Validating Subject ALternative Name {}" , subjectAltName);

        final List<SubjectAltNameField> entitySAN = subjectAltName.getSubjectAltNameFields();

        if (entitySAN == null || entitySAN.isEmpty()) {
            return;
        }
        for (final SubjectAltNameField subjectAltNameField : entitySAN) {

            subjectAltNameValidator.validate(subjectAltNameField);
        }
    }

    /**
     * check weather {@link CertificateAuthority} can eligible to deleted with {@link CAStatus}
     * 
     * @param caStatus
     *            {@link CAStatus} caStatus that specifies deletion is possible or not.
     * @return true/exception
     * @throws CoreEntityInUseException
     *             Thrown when the CA has Active Certificates.
     */
    public boolean isCACanBeDeleted(final CAStatus caStatus) throws CoreEntityInUseException {

        if (caStatus == CAStatus.DELETED) {
            logger.info(EntityManagementErrorCodes.CA_ENTITY_IS_DELETED);
        } else if (caStatus == CAStatus.ACTIVE) {
            logger.error(EntityManagementErrorCodes.CA_ENTITY_IS_ACTIVE);
            throw new CoreEntityInUseException(EntityManagementErrorCodes.CA_ENTITY_IS_ACTIVE);
        }
        return true;
    }

    /**
     * check weather caEntityName has {@link CertificateAuthorityData / EntityData} list
     * 
     * @param caEntityName
     * @throws CoreEntityInUseException
     *             in case of CA has Active Certificates
     * @throws CoreEntityServiceException
     *             in case of db errors for entity related operations
     */
    public void checkCAEntityHasEntities(final String caEntityName) throws CoreEntityInUseException, CoreEntityServiceException {

        final List<CertificateAuthorityData> subCAList = cAEntityPersistenceHandler.getSubCAsUnderCA(caEntityName);

        if (ValidationUtils.isNullOrEmpty(subCAList)) {
            cAEntityPersistenceHandler.checkEntityUnderCA(caEntityName);
        } else {
            cAEntityPersistenceHandler.checkSubCAsUnderCA(subCAList);
        }
    }

    /**
     * Check complete SubCAs hierarchy under SubCA
     * 
     * @param subCAList
     * 
     * @throws CoreEntityInUseException
     *             thrown when the CA has active certificates.
     */
    public void checkSubCAsUnderCA(final List<CertificateAuthorityData> subCAList) throws CoreEntityInUseException {
        final List<String> caEntityNameList = new ArrayList<>();
        
        for (final CertificateAuthorityData certificateAuthorityData : subCAList) {
            if (certificateAuthorityData.getStatus() == CAStatus.ACTIVE) {
                logger.error(EntityManagementErrorCodes.CAENTITY_IS_ACTIVE_UNDER_CA);
                throw new CoreEntityInUseException(EntityManagementErrorCodes.CAENTITY_IS_ACTIVE_UNDER_CA);
            }
            caEntityNameList.add(certificateAuthorityData.getName());
        }
        for (final CertificateAuthorityData certificateAuthorityData : subCAList) {
            final List<CertificateAuthorityData> subCAListData = cAEntityPersistenceHandler.getSubCAsUnderCA(certificateAuthorityData.getName());
            checkSubCAsUnderCA(subCAListData);
        }
    }

    /**
     * @param certificateAuthority
     */
    private void validateForInvalidObjects(final CertificateAuthority certificateAuthority) {
        if (certificateAuthority == null) {
            throw new IllegalArgumentException(EntityManagementErrorCodes.CA_ISNOTNULL);
        }
        if (certificateAuthority.getName() == null) {
            throw new IllegalArgumentException(EntityManagementErrorCodes.NAME_ISNOTNULL);
        }
        if (certificateAuthority.getName().trim().isEmpty()) {
            throw new IllegalArgumentException(EntityManagementErrorCodes.NAME_ISNOTEMPTY);
        }

    }

    /**
     * This method validates the CrlGenerationinfo mandatory attributes and validates the format of the data in each of the attributes.
     * 
     * @param crlGenerationInfoList
     *            is the crlGenerationinfo associated for a given CertificateAuthority
     * @throws IllegalArgumentException
     *             is thrown when a mandatory argument is missing or invalid data is set for an attribute
     */

    private void validateCrlGenerationInfo(final List<CrlGenerationInfo> crlGenerationInfoList) throws IllegalArgumentException {
        if (crlGenerationInfoList != null) {
            for (CrlGenerationInfo crlGenerationInfo : crlGenerationInfoList) {
                if (crlGenerationInfo.getVersion() == null) {
                    throw new IllegalArgumentException("Missing mandatory attribute CRLVersion in CRL GenerationIfno.");
                }
                //Code commented as TORF-66997 is not implemented yet
                //Bug : TORF-209127
                /*if (crlGenerationInfo.getSignatureAlgorithm() != null) {
                    logger.debug("Validating SignatureAlgorithm in CRLGenerationInfo");
                    validateSignatureAlgorithm(crlGenerationInfo.getSignatureAlgorithm());
                }*/
                validateDurationFormat(crlGenerationInfo.getSkewCrlTime(), "SkewCrlTime");
                validateDurationFormat(crlGenerationInfo.getOverlapPeriod(), "CRL OverLapPeriod");
                validateValidtyPeriod(crlGenerationInfo.getValidityPeriod());

            }
        } else {
            logger.info("CRLGenerationInfo not provided for the CA");
        }

    }

    /**
     * This method validates the ValidityPeriod attribute of the CRLGenerationInfo of a CertificateAuthority
     * 
     * @param validityPeriod
     *            is the validity date of a Crl
     * @throws IllegalArgumentException
     *             is thrown when a mandatory argument is missing or invalid data is set for an attribute
     */
    private void validateValidtyPeriod(final Duration validityPeriod) throws IllegalArgumentException {
        if (validityPeriod == null) {
            throw new IllegalArgumentException("Missing validityPeriod for CRLGenerationInfo");
        }
        validateDurationFormat(validityPeriod, "CRL ValidityPeriod");
    }

    /**
     * This method validate the Duration format
     * 
     * @param duration
     *            is the XML datatype duration
     * @param fieldType
     *            is the type of the datatype to which the duration has to be converted
     * @throws IllegalArgumentException
     *             is thrown when a mandatory argument is missing or invalid data is set for an attribute
     */
    private void validateDurationFormat(final Duration duration, final String fieldType) throws IllegalArgumentException {
        logger.debug("Validating {} in CertificateProfile{}", fieldType, duration);

        if (duration == null) {
            return;
        }

        if (!ValidationUtils.validateDurationFormat(duration)) {
            logger.debug("Invalid {} in CertificateProfile{}", fieldType, duration);
            throw new IllegalArgumentException("Invalid profile attribute : CRLGenerationInfo." + fieldType);
        }

    }

    /**
     * This method validates the Signature Algorithm present as a part of CrlGenerationInfo
     * 
     * @param signatureAlgorithm
     *            is the value of the signature algorithm
     * @throws AlgorithmValidationException
     *             is thrown when the SignatureAlgorithm validation fails.
     */
    //Code commented as TORF-66997 is not implemented yet
    //Bug : TORF-209127
    /*private void validateSignatureAlgorithm(final Algorithm signatureAlgorithm) throws AlgorithmValidationException {
        logger.debug("Validating Signature Algorithm in Certificate Profile {}", signatureAlgorithm);

        if (signatureAlgorithm == null) {
            logger.error("SignatureAlgorithm cannot be null");
            throw new AlgorithmValidationException("SignatureAlgorithm cannot be null");
        }

        final AlgorithmData algorithmDataFromDB = algorithmPersistenceHandler.getAlgorithmByNameAndType(signatureAlgorithm, AlgorithmType.SIGNATURE_ALGORITHM);

        if (algorithmDataFromDB == null) {
            logger.error("Given signature algorithm not found or not supported or of invalid category{}", signatureAlgorithm.getName());
            throw new AlgorithmValidationException("Given signature algorithm not found or not supported or of invalid category{}");

        }
    }*/

}
