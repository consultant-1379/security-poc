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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.impl;

import java.io.IOException;

import java.security.PublicKey;
import java.util.List;

import javax.inject.Inject;

import org.bouncycastle.asn1.x509.Extension;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.kaps.certificate.exception.InvalidCertificateExtensionsException;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyIdentifierNotFoundException;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.kaps.model.holder.CertificateExtensionHolder;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.builder.ExtensionBuilder;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.persistence.handler.CertificateRequestPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.certificatemanagement.validator.AlgorithmValidator;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.eserviceproxy.KeyAccessProviderServiceProxy;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.CertificateModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.KeyIdentifierModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.CertificatePersistenceHelper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.handler.KeyPairPersistenceHandler;
import com.ericsson.oss.itpf.security.pki.core.common.utils.CertificateGenerationInfoParser;
import com.ericsson.oss.itpf.security.pki.core.exception.configuration.AlgorithmValidationException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityServiceException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.KeyPairGenerationException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateServiceException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificaterequest.CertificateRequestGenerationException;

/**
 * Class which does CSR related operations.
 */
public class CSRManager {

    @Inject
    KeyIdentifierModelMapper keyIdentifierModelMapper;

    @Inject
    CertificateModelMapper certificateModelMapper;

    @Inject
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Inject
    KeyPairPersistenceHandler keyPairPersistenceHandler;

    @Inject
    CertificateRequestPersistenceHandler certificateRequestPersistenceHandler;

    @Inject
    KeyAccessProviderServiceProxy keyAccessProviderServiceProxy;

    @Inject
    ExtensionBuilder extensionBuilder;

    @Inject
    AlgorithmValidator algorithmValidator;

    @Inject
    CertificateGenerationInfoParser certGenInfoParser;

    @Inject
    Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    /**
     * Generates and exports CSR using certificateGenerationInfo.
     * 
     * @param certificateGenerationInfo
     *            {@link CertificateGenerationInfo}
     * @return {@link PKCS10CertificationRequestHolder} object
     * @throws AlgorithmValidationException
     *             Thrown when Algorithm validation has failed
     * @throws CertificateRequestGenerationException
     *             Thrown when any exception occurs when generating CSR.
     * @throws CertificateServiceException
     *             Thrown when any internal db error occurs while generating CSR.
     * @throws CoreEntityNotFoundException
     *             Thrown in case provided CertificateAuthority does not exist in the database.
     * @throws CoreEntityServiceException
     *             Thrown for any entity related database errors in PKI Core.
     * @throws KeyPairGenerationException
     *             Thrown to indicate that KeyPair could not be generated.
     */
    public PKCS10CertificationRequestHolder generateCSR(final CertificateGenerationInfo certificateGenerationInfo) throws AlgorithmValidationException, CertificateRequestGenerationException,
            CertificateServiceException, CoreEntityNotFoundException, CoreEntityServiceException {

        try {
            // Validate
            validateAlgorithms(certificateGenerationInfo.getKeyGenerationAlgorithm(), certificateGenerationInfo.getSignatureAlgorithm());

            // Prepare info required to generate CSR
            final CertificateAuthorityData certificateAuthorityData = certificatePersistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName());
            final String subjectDN = certificateGenerationInfo.getCAEntityInfo().getSubject().toASN1String();
            logger.info("preparing information required to generate Root CA CSR {} ", certificateGenerationInfo.getCAEntityInfo().getName());

            final String signatureAlgorithm = certificateGenerationInfo.getSignatureAlgorithm().getName();

            final KeyIdentifier keyIdentifier = keyPairPersistenceHandler.getKeyIdentifierOfCA(certificateGenerationInfo);

            final PublicKey publicKey = keyAccessProviderServiceProxy.getKeyAccessProviderService().getPublicKey(keyIdentifier);

            final List<Extension> certificateExtensions = extensionBuilder.buildCertificateExtensions(certificateGenerationInfo, publicKey);
            final List<CertificateExtensionHolder> extensionsHolder = extensionBuilder.getCertificateExtensionHolders(certificateExtensions);

            // Call Kaps to generate CSR
            final PKCS10CertificationRequestHolder certificationRequestHolder = keyAccessProviderServiceProxy.getKeyAccessProviderService().generateCSR(keyIdentifier, signatureAlgorithm, subjectDN, extensionsHolder);

            certificateGenerationInfo.setForExternalCA(true);
            // Store CertificateGenerationInfo and CSR in database and return CSR
            certificateRequestPersistenceHandler.storeCertificateGenerationInfo(certificateGenerationInfo, certificationRequestHolder.getCertificateRequest().getEncoded(), certificateAuthorityData,
                    null);

            systemRecorder.recordSecurityEvent("PKICore.GENERATECSR", "CSRManager", "CSR for Root CA is generated for "
                    + certificateGenerationInfo.getCAEntityInfo().getName(), "PKICORE.EXPORT_CSR", ErrorSeverity.INFORMATIONAL, "SUCCESS");
            return certificationRequestHolder;

        } catch (IOException ioException) {
            logger.error(ErrorMessages.INVALID_CSR_ENCODING, ioException);
            systemRecorder.recordError("PKICore.GENERATECSR", ErrorSeverity.ERROR, "CSRManager", "CertificateGenerationInfo",
                    "CSR encoding is not valid or not in correct format for entity " + certificateGenerationInfo.getCAEntityInfo().getName());
            throw new CertificateRequestGenerationException(ErrorMessages.INVALID_CSR_ENCODING);
        } catch (com.ericsson.oss.itpf.security.kaps.certificate.exception.CSRGenerationException csrGenerationException) {
            logger.error(csrGenerationException.getMessage(), csrGenerationException);
            systemRecorder.recordError("PKICore.GENERATECSR", ErrorSeverity.ERROR, "CSRManager", "CertificateGenerationInfo",
                    "Unable to generate CSR for the CA " + certificateGenerationInfo.getCAEntityInfo().getName());
            throw new CertificateRequestGenerationException(ErrorMessages.UNABLE_TO_GENERATE_CSR_FOR_CA_FROM_KAPS);
        } catch (KeyIdentifierNotFoundException keyIdentifierNotFoundException) {
            logger.error(keyIdentifierNotFoundException.getMessage(), keyIdentifierNotFoundException);
            systemRecorder.recordError("PKICore.GENERATECSR", ErrorSeverity.ERROR, "CSRManager", "CertificateGenerationInfo",
                    "Active Key Pair does not exist for CA " + certificateGenerationInfo.getCAEntityInfo().getName());
            throw new CertificateRequestGenerationException(ErrorMessages.UNABLE_TO_GET_KEY_WITH_KEYIDENTIFIER);
        } catch (KeyAccessProviderServiceException keyAccessProviderServiceException) {
            logger.error(keyAccessProviderServiceException.getMessage(), keyAccessProviderServiceException);
            systemRecorder.recordError("PKICore.GENERATECSR", ErrorSeverity.ERROR, "CSRManager", "CertificateGenerationInfo",
                    "Key acess provider exception, Unable to generate CSR for the CA " + certificateGenerationInfo.getCAEntityInfo().getName());
            throw new CertificateServiceException(ErrorMessages.UNABLE_TO_GENERATE_CSR_FOR_CA_FROM_KAPS);
        } catch (final com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.InvalidCertificateExtensionsException invalidCertificateExtensionsException) {
            logger.error(invalidCertificateExtensionsException.getMessage(), invalidCertificateExtensionsException);
            systemRecorder.recordError("PKICore.GENERATECSR", ErrorSeverity.ERROR, "CSRManager", "CertificateGenerationInfo",
                    "Error occurred while building certificate extension for generating CSR "+ certificateGenerationInfo.getCAEntityInfo().getName());
            throw new CertificateRequestGenerationException(ErrorMessages.EXTENSIONS_BUILDING_FAILED);
        } catch (AlgorithmValidationException algorithmValidationException) {
            logger.error(algorithmValidationException.getMessage(), algorithmValidationException);
            systemRecorder.recordError("PKICore.GENERATECSR", ErrorSeverity.ERROR, "CSRManager", "CertificateGenerationInfo",
                    "Algorithm validation exception for entity " + certificateGenerationInfo.getCAEntityInfo().getName());
            throw new CertificateRequestGenerationException(algorithmValidationException.getMessage());
        } catch (KeyPairGenerationException keyPairGenerationException) {
            logger.error(keyPairGenerationException.getMessage(), keyPairGenerationException);
            systemRecorder.recordError("PKICore.GENERATECSR", ErrorSeverity.ERROR, "CSRManager", "CertificateGenerationInfo",
                    "Key Pair generation exception for" + certificateGenerationInfo.getCAEntityInfo().getName());
            throw new CertificateRequestGenerationException(keyPairGenerationException.getMessage());
        } catch (final Exception exception) {
            logger.error(exception.getMessage(), exception);
            systemRecorder.recordError("PKICore.GENERATECSR", ErrorSeverity.ERROR, "CSRManager", "CertificateGenerationInfo",
                    "Unknown error has occured for " + certificateGenerationInfo.getCAEntityInfo().getName());
            throw new CertificateRequestGenerationException(exception.getMessage());
        }

    }

    private void validateAlgorithms(final Algorithm... algorithms) throws AlgorithmValidationException {

        for (Algorithm algorithm : algorithms) {

            logger.debug("Validating algorithm {} in pki core", algorithm.getName());

            algorithmValidator.validateAlgorithm(algorithm);
            logger.debug("Algorithm {} validated successfully ", algorithm.getName());
        }
    }

}
