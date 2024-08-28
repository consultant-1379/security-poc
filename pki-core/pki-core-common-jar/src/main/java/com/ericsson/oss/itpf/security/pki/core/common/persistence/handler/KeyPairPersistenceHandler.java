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
package com.ericsson.oss.itpf.security.pki.core.common.persistence.handler;

import javax.inject.Inject;
import javax.persistence.EntityExistsException;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.kaps.exception.NotSupportedException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyIdentifierNotFoundException;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.kaps.model.KeyPairStatus;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateGenerationInfo;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.RequestType;
import com.ericsson.oss.itpf.security.pki.core.common.constants.Constants;
import com.ericsson.oss.itpf.security.pki.core.common.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.core.common.eserviceproxy.KeyAccessProviderServiceProxy;
import com.ericsson.oss.itpf.security.pki.core.common.modelmapper.KeyIdentifierModelMapper;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.CertificateAuthorityData;
import com.ericsson.oss.itpf.security.pki.core.common.persistence.entity.KeyIdentifierData;
import com.ericsson.oss.itpf.security.pki.core.exception.entitymanagement.CoreEntityNotFoundException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.KeyPairGenerationException;
import com.ericsson.oss.itpf.security.pki.core.exception.security.certificate.CertificateServiceException;

/**
 * This class does the operations related to key management.
 *
 */
public class KeyPairPersistenceHandler {

    @Inject
    KeyAccessProviderServiceProxy keyAccessProviderServiceProxy;

    @Inject
    CertificatePersistenceHelper certificatePersistenceHelper;

    @Inject
    KeyIdentifierModelMapper keyIdentifierModelMapper;

    @Inject
    Logger logger;

    @Inject
    private SystemRecorder systemRecorder;

    private void updateActiveCAKeysToInActive(final KeyIdentifierData keyIdentifierData) throws KeyAccessProviderServiceException, KeyIdentifierNotFoundException, NotSupportedException,
            PersistenceException {

        certificatePersistenceHelper.updateKeyIdentifierStatus(keyIdentifierData, KeyPairStatus.INACTIVE);
        final KeyIdentifier keyIdentifier = keyIdentifierModelMapper.toModel(keyIdentifierData);
        keyAccessProviderServiceProxy.getKeyAccessProviderService().updateKeyPairStatus(keyIdentifier, KeyPairStatus.INACTIVE);

    }

    private KeyIdentifierData generateAndStoreCAKeys(final String caName, String keyGenerationAlgorithm, final int keySize) throws KeyAccessProviderServiceException, KeyPairGenerationException {

        try {
            if (keyGenerationAlgorithm.equals(Constants.ECDSA_ALGORITHM_NAME)) {
                validateECDSAKeysize(keySize);
                keyGenerationAlgorithm = Constants.EC_ALGORITHM_NAME;
            }

            final KeyIdentifier keyIdentifier = keyAccessProviderServiceProxy.getKeyAccessProviderService().generateKeyPair(keyGenerationAlgorithm, keySize);
            final KeyIdentifierData keyIdentifierData = certificatePersistenceHelper.storeAndReturnKeyData(keyIdentifierModelMapper.fromModel(keyIdentifier, KeyPairStatus.ACTIVE));

            return keyIdentifierData;
        } catch (final com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyPairGenerationException keyPairGenerationException) {
            logger.error(ErrorMessages.ERROR_GENERATING_KEY_PAIR + " " + caName, keyPairGenerationException);
            throw new KeyPairGenerationException(ErrorMessages.ERROR_GENERATING_KEY_PAIR + caName);
        } catch (final EntityExistsException entityExistsException) {
            logger.error(entityExistsException.getMessage() + " " + caName, entityExistsException);
            throw new KeyPairGenerationException(entityExistsException.getMessage());
        }
    }

    /**
     * Gets the Active key identifier of the CA.
     * 
     * @param certificateGenerationInfo
     *            {@link CertificateGenerationInfo}
     * @return active key identifier of the CA.
     * @throws CertificateServiceException
     *             Thrown for any certificate related database errors in PKI Core.
     * @throws CoreEntityNotFoundException
     *             in case of entity not found the in the system.
     * @throws KeyPairGenerationException
     *             Thrown to indicate that KeyPair could not be generated.
     */
    public KeyIdentifierData getKeyIdentifierDataOfCA(final CertificateGenerationInfo certificateGenerationInfo) throws CertificateServiceException, CoreEntityNotFoundException,
            KeyPairGenerationException {

        logger.debug("Getting key identifier data of CA: {}", certificateGenerationInfo.getCAEntityInfo().getName());
        try {
            final KeyIdentifierData keyIdentifierData = certificatePersistenceHelper.getActiveKeyIdentifier(certificateGenerationInfo.getCAEntityInfo().getName());

            if (keyIdentifierData != null && certificateGenerationInfo.getRequestType() != RequestType.REKEY) {
                return keyIdentifierData;
            }

            if (keyIdentifierData != null) {
                updateActiveCAKeysToInActive(keyIdentifierData);
            }

            final KeyIdentifierData keyData = generateAndStoreCAKeys(certificateGenerationInfo.getCAEntityInfo().getName(), certificateGenerationInfo.getKeyGenerationAlgorithm().getName(),
                    certificateGenerationInfo.getKeyGenerationAlgorithm().getKeySize());

            final CertificateAuthorityData certificateAuthorityData = certificatePersistenceHelper.getCA(certificateGenerationInfo.getCAEntityInfo().getName());
            certificatePersistenceHelper.updateCAWithActiveKeys(certificateAuthorityData, keyData);

            logger.info("Returning Key identifier data for CA Entity: {}", certificateGenerationInfo.getCAEntityInfo().getName());
            return keyData;

        } catch (PersistenceException persistenceException) {
            logger.error(ErrorMessages.UNABLE_TO_UPDATE_WITH_KEYIDENTIFIERDATA);
            systemRecorder.recordError("PKICORE.CertificateManagement", ErrorSeverity.ERROR, "KeyPairPersistenceHandler", "CertificateGenerationInfo",
                    "Unable to upadate KeyIdentifierData for CA: " + certificateGenerationInfo.getCAEntityInfo().getName());
            throw new KeyPairGenerationException(ErrorMessages.UNABLE_TO_UPDATE_WITH_KEYIDENTIFIERDATA, persistenceException);
        } catch (NotSupportedException notSupportedException) {
            logger.error(notSupportedException.getMessage());
            systemRecorder.recordError("PKICORE.CertificateManagement", ErrorSeverity.ERROR, "KeyPairPersistenceHandler", "CertificateGenerationInfo",
                    "Not supported exception while fetching Key identifier data of CA: " + certificateGenerationInfo.getCAEntityInfo().getName());
            throw new KeyPairGenerationException(notSupportedException.getMessage(), notSupportedException);
        } catch (KeyAccessProviderServiceException keyAccessProviderServiceException) {
            logger.error(ErrorMessages.UNABLE_TO_UPDATE_WITH_KEYIDENTIFIERDATA);
            systemRecorder.recordError("PKICORE.CertificateManagement", ErrorSeverity.ERROR, "KeyPairPersistenceHandler", "CertificateGenerationInfo",
                    "Key access service provider exception while fetching Key identifier data of CA: " + certificateGenerationInfo.getCAEntityInfo().getName());
            throw new KeyPairGenerationException(ErrorMessages.UNABLE_TO_UPDATE_WITH_KEYIDENTIFIERDATA, keyAccessProviderServiceException);
        } catch (KeyIdentifierNotFoundException keyIdentifierNotFoundException) {
            logger.error(ErrorMessages.UNABLE_TO_GET_KEY_WITH_KEYIDENTIFIER);
            systemRecorder.recordError("PKICORE.CertificateManagement", ErrorSeverity.ERROR, "KeyPairPersistenceHandler", "CertificateGenerationInfo",
                    "Key identifier not found exception while fetching Key identifier data of CA: " + certificateGenerationInfo.getCAEntityInfo().getName());
            throw new KeyPairGenerationException(ErrorMessages.UNABLE_TO_GET_KEY_WITH_KEYIDENTIFIER, keyIdentifierNotFoundException);
        }
    }

    /**
     * Gets the Active key identifier of the CA.
     * 
     * @param certificateGenerationInfo
     *            {@link CertificateGenerationInfo}
     * @return active key identifier of the CA.
     * @throws CertificateServiceException
     *             Thrown for any certificate related database errors in PKI Core.
     * 
     * @throws CoreEntityNotFoundException
     *             Thrown in case of entity not found in the system.
     * @throws KeyPairGenerationException
     *             thrown to indicate that KeyPair could not be generated
     */
    public KeyIdentifier getKeyIdentifierOfCA(final CertificateGenerationInfo certificateGenerationInfo) throws CertificateServiceException, CoreEntityNotFoundException, KeyPairGenerationException {

        logger.debug("Fetching Key identifier for CA: {}", certificateGenerationInfo.getCAEntityInfo().getName());
        final KeyIdentifierData keyIdentifierData = getKeyIdentifierDataOfCA(certificateGenerationInfo);
         keyIdentifierModelMapper.toModel(keyIdentifierData);
        return keyIdentifierModelMapper.toModel(keyIdentifierData);
    }

    /**
     * Validates ECDSA algorithms for weak and not supported key sizes.
     * 
     * @param keySize
     *            key Size of Algorithm.
     * @throws KeyPairGenerationException
     *             Thrown in case weak size for ECDSA algorithm.
     */
    public void validateECDSAKeysize(final Integer keySize) throws KeyPairGenerationException {
        if (keySize == 512) {
            logger.error(ErrorMessages.ECDSA_KEY_SIZE_NOT_SUPPORTED);
            throw new KeyPairGenerationException(ErrorMessages.ECDSA_KEY_SIZE_NOT_SUPPORTED);
        }
        if (keySize == 160 || keySize == 163) {
            logger.error(ErrorMessages.ECDSA_KEY_SIZE_WEAK);
            throw new KeyPairGenerationException(ErrorMessages.ECDSA_KEY_SIZE_WEAK);
        }
    }
}
