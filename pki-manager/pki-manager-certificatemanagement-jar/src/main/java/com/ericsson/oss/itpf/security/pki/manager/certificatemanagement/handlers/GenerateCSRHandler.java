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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.handlers;

import java.io.IOException;


import javax.inject.Inject;

import org.slf4j.Logger;


import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.RequestType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.common.util.CertificateRequestUtility;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.builder.CertificateGenerationInfoBuilder;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.eservice.CertificatemanagementEserviceProxy;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.helper.EntityHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.common.modelmapper.entity.CAEntityMapper;
import com.ericsson.oss.itpf.security.pki.manager.common.persistence.handler.certificate.CACertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.manager.common.qualifers.EntityQualifier;
import com.ericsson.oss.itpf.security.pki.manager.common.utils.SubjectUtils;
import com.ericsson.oss.itpf.security.pki.manager.exception.InvalidOperationException;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.CANotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.entity.caentity.InvalidCAException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.CertificateRequestGenerationException;
import com.ericsson.oss.itpf.security.pki.manager.model.EntityType;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CAEntityData;

/**
 *
 * Class used for CSR related operations
 *
 * @author xvambur
 *
 */
public class GenerateCSRHandler {

    @Inject
    EntityHelper entityHelper;

    @Inject
    CertificateGenerationInfoBuilder certificateGenerationInfoBuilder;

    @Inject
    CACertificatePersistenceHelper caPersistenceHelper;

    @Inject
    @EntityQualifier(EntityType.CA_ENTITY)
    CAEntityMapper caEntityMapper;

    @Inject
    Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    @Inject
    CertificatemanagementEserviceProxy certificatemanagementEserviceProxy;

    /**
     * Returns CSR {@link PKCS10CertificationRequestHolder} for the given Root CA Entity Name.
     *
     * @param rootCAName
     *            Name of the Root CA Entity for which CSR needs to be generated.
     * @param newKey
     *            If newKey flag is set to true, then CSR is generated using a new KeyPair.
     * @return {@link PKCS10CertificationRequestHolder}
     * @throws AlgorithmNotFoundException
     * @throws CANotFoundException
     *             Thrown when given CAEntity doesn't exists.
     * @throws CertificateRequestGenerationException
     *             Thrown when CertificateRequest generation or export is failed.
     * @throws CertificateServiceException
     *             Thrown to indicate any internal database errors or any unconditional exceptions.
     * @throws InvalidCAException
     *             Thrown when the given CA is not active.
     * @throws InvalidEntityAttributeException
     *             Thrown when the given entity has invalid attribute.
     */
    public PKCS10CertificationRequestHolder generateCSR(final String rootCAName, final boolean newKey) throws AlgorithmNotFoundException, CANotFoundException, CertificateRequestGenerationException,
            CertificateServiceException, InvalidCAException, InvalidEntityAttributeException {

        return generatePKCS10CertificateRequestHolder(rootCAName, newKey);

    }

    private PKCS10CertificationRequestHolder generatePKCS10CertificateRequestHolder(final String rootCAName, final boolean newKey) throws AlgorithmNotFoundException, CANotFoundException,
            CertificateRequestGenerationException, CertificateServiceException, InvalidCAException, InvalidEntityAttributeException {
        PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = null;

        // Get Root CA Entity
        final CAEntity rootCAEntity = getRootCAEntity(rootCAName);
        //TORF-143242 - Removing DNQ from the Certificate unblock the AMOS issue
        SubjectUtils.removeDNQFromSubject(rootCAEntity.getCertificateAuthority().getSubject());
        pkcs10CertificationRequestHolder = generateCSR(rootCAName, newKey, rootCAEntity);
        systemRecorder.recordSecurityEvent("PKI_MANAGER.EXPORT_CSR", "ExportCSRHandler", "CSR is generated for Root CA " + rootCAName, "EXPORT_CSR", ErrorSeverity.INFORMATIONAL, "SUCCESS");

        return pkcs10CertificationRequestHolder;
    }

    private PKCS10CertificationRequestHolder generateCSR(final String rootCAName, final boolean newKey, final CAEntity rootCAEntity) throws AlgorithmNotFoundException, CANotFoundException,
            CertificateRequestGenerationException, CertificateServiceException, InvalidCAException, InvalidEntityAttributeException {
        CertificateGenerationInfo certificateGenerationInfo;
        PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder;
        // Build CertificateGenerationInfo
        certificateGenerationInfo = buildCertificateGenerationInfo(rootCAEntity, newKey);

        try {
            certificateGenerationInfo.setForExternalCA(true);
            // Store CertificateGenerationInfo in PKI-Manager DB.
            caPersistenceHelper.storeCertificateGenerateInfo(certificateGenerationInfo);

            // Call to PKI-Core to Generate and Export CSR
            pkcs10CertificationRequestHolder = invokePKICoreExportCSR(certificateGenerationInfo);
            logger.debug("Received CSR from from PKI-Core for Root CA {} ", rootCAName);

            // Update CertificateGenerationInfo with generated CSR
            caPersistenceHelper.updateCertificateGenerateInfoWithCSR(certificateGenerationInfo, pkcs10CertificationRequestHolder.getCertificateRequest().getEncoded());

        } catch (IOException ioException) {
            logger.error(ErrorMessages.CSR_ENCODING_FAILED, ioException.getMessage());
            throw new CertificateRequestGenerationException(ErrorMessages.CSR_ENCODING_FAILED + ioException);
        }
        return pkcs10CertificationRequestHolder;
    }

    /**
     * This method is used to fetch latest CSR for the given CA from the database.
     *
     * @param caName
     *            for which latest CSR has to be fetched.
     * @return CSR in PKCS10CertificationRequestHolder object.
     * @throws CertificateRequestGenerationException
     *             is thrown when internal error occurs while fetching csr.
     * @throws CertificateServiceException
     *             is thrown when internal db error occurs while fetching csr.
     * @throws InvalidOperationException
     *             Thrown when the certificateGenerationInfo is not found.
     */
    public PKCS10CertificationRequestHolder getCSR(final String caName) throws CertificateRequestGenerationException, CertificateServiceException, InvalidOperationException {
        PKCS10CertificationRequestHolder certificateRequestHolder = null;
        try {

            final byte[] csr = caPersistenceHelper.getCSR(caName);
            certificateRequestHolder = CertificateRequestUtility.getCertificateRequestHolder(csr);

        } catch (IOException ioException) {
            logger.error(ErrorMessages.PKCS10_CERTIFICATE_REQUEST_GENERATION_FAILED, " while generating PKCS10CertificationRequestHolder holder object for CA name {} ", caName, "{}",
                    ioException.getMessage());
            throw new CertificateRequestGenerationException(ErrorMessages.PKCS10_CERTIFICATE_REQUEST_GENERATION_FAILED, ioException);
        }
        return certificateRequestHolder;
    }

    private CertificateGenerationInfo buildCertificateGenerationInfo(final CAEntity rootCAEntity, final boolean newKey) throws CANotFoundException, CertificateServiceException, InvalidCAException,
            InvalidEntityAttributeException {

        CertificateGenerationInfo certificateGenerationInfo = null;

        final Algorithm keyGenerationAlgorithm = entityHelper.getOverridenKeyGenerationAlgorithm(rootCAEntity);
        rootCAEntity.setKeyGenerationAlgorithm(keyGenerationAlgorithm);
        try {

            if (newKey) {
                certificateGenerationInfo = certificateGenerationInfoBuilder.build(rootCAEntity, RequestType.REKEY);
            } else {
                certificateGenerationInfo = certificateGenerationInfoBuilder.build(rootCAEntity, RequestType.RENEW);
            }
        } catch (CAEntityNotInternalException entityNotFoundException) {
            logger.error(" Unable to find the CA ");
            throw new CANotFoundException(ErrorMessages.CA_ENTITY_NOT_FOUND + entityNotFoundException.getMessage(), entityNotFoundException);
        }
        return certificateGenerationInfo;
    }

    public CAEntity getRootCAEntity(final String rootCAName) throws CANotFoundException, CertificateServiceException, InvalidEntityAttributeException {

        CAEntityData caEntityData = null;
        try {
            caEntityData = caPersistenceHelper.getCAEntity(rootCAName);
        } catch (EntityServiceException entityServiceException) {
            logger.error(ErrorMessages.INTERNAL_ERROR, entityServiceException.getMessage());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR, entityServiceException);
        } catch (CANotFoundException caNotFoundException) {
            logger.error(ErrorMessages.ROOT_CA_NOT_FOUND, caNotFoundException.getMessage());
            systemRecorder.recordError("PKI_MANAGER.EXPORT_CSR_FAIL", ErrorSeverity.ERROR, "ExportCSRHandler", "ExportCSR", ErrorMessages.ROOT_CA_NOT_FOUND);
            throw new CANotFoundException(ErrorMessages.ROOT_CA_NOT_FOUND, caNotFoundException);
        }

        CAEntity caEntity = null;
        try {
            caEntity = caEntityMapper.toAPIFromModel(caEntityData);
        } catch (CAEntityNotInternalException caNotFoundException) {
            logger.error(ErrorMessages.ROOT_CA_NOT_FOUND, caNotFoundException.getMessage());
            systemRecorder.recordError("PKI_MANAGER.EXPORT_CSR_FAIL", ErrorSeverity.ERROR, "ExportCSRHandler", "ExportCSR", ErrorMessages.ROOT_CA_NOT_FOUND);
            throw new CANotFoundException(ErrorMessages.ROOT_CA_NOT_FOUND, caNotFoundException);
        }
        return caEntity;
    }

    private PKCS10CertificationRequestHolder invokePKICoreExportCSR(final CertificateGenerationInfo certificateGenerationInfo) throws AlgorithmNotFoundException, CANotFoundException,
            CertificateRequestGenerationException, CertificateServiceException {

        PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = null;

        try {
            pkcs10CertificationRequestHolder = certificatemanagementEserviceProxy.getCoreCertificateManagementService().generateCSR(certificateGenerationInfo);

        } catch (com.ericsson.oss.itpf.security.pki.core.exception.configuration.AlgorithmValidationException validationException) {
            logger.error(ErrorMessages.ALGORITHM_NOT_FOUND, validationException.getMessage());
            throw new AlgorithmNotFoundException(ErrorMessages.ALGORITHM_NOT_FOUND + validationException);
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException entityNotFoundException) {
            logger.error(ErrorMessages.ROOT_CA_NOT_FOUND, entityNotFoundException.getMessage());
            throw new CANotFoundException(ErrorMessages.ROOT_CA_NOT_FOUND + entityNotFoundException);
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.CertificateRequestGenerationException csrGenerationException) {
            logger.error(ErrorMessages.CSR_GENERATION_FAILED, csrGenerationException.getMessage());
            throw new CertificateRequestGenerationException(ErrorMessages.CSR_GENERATION_FAILED, csrGenerationException);
        } catch (com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException
                | com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateServiceException exception) {
            logger.error(ErrorMessages.INTERNAL_ERROR, exception.getMessage());
            throw new CertificateServiceException(ErrorMessages.INTERNAL_ERROR + exception);
        }

        return pkcs10CertificationRequestHolder;
    }
}
