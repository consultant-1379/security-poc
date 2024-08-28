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
package com.ericsson.oss.itpf.security.kaps.common.persistence.handler;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.X509EncodedKeySpec;
import java.util.Date;

import javax.inject.Inject;
import javax.persistence.PersistenceException;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.kaps.common.ErrorMessages;
import com.ericsson.oss.itpf.security.kaps.common.exception.KeyDecryptionException;
import com.ericsson.oss.itpf.security.kaps.common.exception.KeyEncryptionException;
import com.ericsson.oss.itpf.security.kaps.common.modelmapper.KeyIdentifierMapper;
import com.ericsson.oss.itpf.security.kaps.common.persistence.KAPSExternalPersistenceManager;
import com.ericsson.oss.itpf.security.kaps.common.persistence.entity.EncryptedPrivateKeyInfoData;
import com.ericsson.oss.itpf.security.kaps.common.persistence.entity.KeyPairInfoData;
import com.ericsson.oss.itpf.security.kaps.common.utils.HashGeneratorUtils;
import com.ericsson.oss.itpf.security.kaps.common.utils.KeyWrapUtils;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyIdentifierNotFoundException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyPairGenerationException;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;
import com.ericsson.oss.itpf.security.kaps.model.KeyPairStatus;

/**
 * Handler class to do the DB operations related to key management.
 *
 */
public class KeyPairPersistenceHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyPairPersistenceHandler.class);
    private static final String KEY_IDENTIFIER_COLUMN = "keyIdentifier";

    @Inject
    KAPSExternalPersistenceManager kapsExternalPersistenceManager;

    @Inject
    KeyIdentifierMapper keyIdentifierMapper;

    @Inject
    KeyWrapUtils keyWrapUtils;

    /**
     * Persists {@link KeyPairInfoData} and returns {@link KeyIdentifier}
     *
     * @param algorithm
     *            Algorithm name.
     * @param modulus
     *            Key size
     * @param keyPair
     *            Key pair to be persisted in the database.
     *
     * @return {@link KeyIdentifier} for the keys.
     *
     * @throws KeyAccessProviderServiceException
     *             Thrown in case of any internal database errors or any unconditional exceptions.
     * @throws KeyPairGenerationException
     *             is thrown if key is not fetched from KeyIdentifier provided
     *
     *
     */
    public KeyIdentifier saveKeyPair(final String algorithm, final int modulus, final KeyPair keyPair) throws KeyAccessProviderServiceException,
            KeyPairGenerationException {

        try {
            final KeyPairInfoData keyPairInfoData = createKeyPairInfoData(algorithm, modulus, keyPair);
            kapsExternalPersistenceManager.createEntity(keyPairInfoData);

            final KeyIdentifier KeyIdentifier = keyIdentifierMapper.toModel(keyPairInfoData.getKeyIdentifier());
            return KeyIdentifier;
        } catch (PersistenceException persistenceException) {
            LOGGER.error(ErrorMessages.UNABLE_TO_GENERATE_KEYPAIR, persistenceException);
            throw new KeyAccessProviderServiceException(ErrorMessages.UNABLE_TO_GENERATE_KEYPAIR, persistenceException);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            LOGGER.error(ErrorMessages.NO_SUCH_AlGORITHM, noSuchAlgorithmException);
            throw new KeyPairGenerationException(ErrorMessages.UNABLE_TO_GENERATE_KEYPAIR, noSuchAlgorithmException);
        } catch (KeyEncryptionException keyEncryptionException) {
            LOGGER.error(ErrorMessages.UNABLE_TO_ENCRYPT, keyEncryptionException);
            throw new KeyPairGenerationException(ErrorMessages.UNABLE_TO_ENCRYPT, keyEncryptionException);
        }
    }

    /**
     * Updates Key pair status
     *
     * @param keyIdentifier
     *            object containing its key identifier.
     * @param keyPairStatus
     *            The {@link KeyPairStatus} object
     *
     * @throws KeyAccessProviderServiceException
     *             Thrown in case of any internal database errors
     * @throws KeyIdentifierNotFoundException
     *             This exception is thrown in case of KeyIdentifier not found.
     */
    public void updateKeyPairInfoStatus(final KeyIdentifier keyIdentifier, final KeyPairStatus keyPairStatus)
            throws KeyAccessProviderServiceException, KeyIdentifierNotFoundException {

        try {
            final KeyPairInfoData keyPairInfoData = getKeyPairInfo(keyIdentifier);
            keyPairInfoData.setKeyPairStatus(keyPairStatus.getId());
            kapsExternalPersistenceManager.updateEntity(keyPairInfoData);
        } catch (PersistenceException persistenceException) {
            LOGGER.error(ErrorMessages.UNABLE_TO_UPDATE_KEYIDENTIFIER, persistenceException);
            throw new KeyAccessProviderServiceException(ErrorMessages.UNABLE_TO_UPDATE_KEYIDENTIFIER, persistenceException);
        }
    }

    /**
     * Returns the {@link PublicKey} from its key identifier.
     *
     * @param keyIdentifier
     *            object containing its key identifier.
     * @return {@link PublicKey} Object
     * 
     * @throws KeyAccessProviderServiceException
     *             is thrown when there are any DB Errors.
     * @throws KeyIdentifierNotFoundException
     *             is thrown if public key is not fetched from KeyIdentifier provided.
     *
     *
     */
    public PublicKey getPublicKey(final KeyIdentifier keyIdentifier) throws KeyAccessProviderServiceException, KeyIdentifierNotFoundException {
        try {
            final KeyPairInfoData keyPairInfoData = getKeyPairInfo(keyIdentifier);
            final KeyFactory keyFactory = KeyFactory.getInstance(keyPairInfoData.getAlgorithm());

            return keyFactory.generatePublic(new X509EncodedKeySpec(keyPairInfoData.getPublickey()));
        } catch (InvalidKeySpecException invalidKeySpecException) {
            LOGGER.error(ErrorMessages.UNABLE_TO_BUILD_PUBLICKEY, invalidKeySpecException);
            throw new KeyAccessProviderServiceException(ErrorMessages.UNABLE_TO_BUILD_PUBLICKEY, invalidKeySpecException);
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            LOGGER.error(ErrorMessages.KEY_GENERATION_ALGORITHM_IS_NOT_SUPPORTED, noSuchAlgorithmException);
            throw new KeyAccessProviderServiceException(ErrorMessages.KEY_GENERATION_ALGORITHM_IS_NOT_SUPPORTED, noSuchAlgorithmException);
        }
    }

    /**
     * Returns the {@link PrivateKey} from its key identifier.
     *
     * @param keyIdentifier
     *            object containing its key identifier.
     *
     * @return {@link PrivateKey}
     *
     * @throws KeyAccessProviderServiceException
     *             is thrown when there are any DB Errors.
     * @throws KeyIdentifierNotFoundException
     *             is thrown if key is not fetched from KeyIdentifier provided
     *
     */
    public PrivateKey getPrivateKey(final KeyIdentifier keyIdentifier) throws KeyAccessProviderServiceException, KeyIdentifierNotFoundException {
        try {
            final KeyPairInfoData keyPairInfoData = getKeyPairInfo(keyIdentifier);

            return keyWrapUtils.decrypt(keyPairInfoData.getEncryptedprivatekeyinfo().getPrivatekey(), keyPairInfoData.getAlgorithm());
        } catch (KeyDecryptionException keyDecryptionException) {
            LOGGER.error(ErrorMessages.UNABLE_TO_BUILD_PRIVATEKEY, keyDecryptionException);
            throw new KeyAccessProviderServiceException(ErrorMessages.UNABLE_TO_BUILD_PRIVATEKEY, keyDecryptionException);
        }
    }

    /**
     * Returns the {@link KeyPairInfoData} from its key identifier.
     *
     * @param keyIdentifier
     *            object containing its key identifier.
     *
     * @return {@link KeyPairInfoData}
     *
     * @throws KeyAccessProviderServiceException
     *             is thrown when there are any DB Errors.
     * @throws KeyIdentifierNotFoundException
     *             is thrown if key is not fetched from KeyIdentifier provided
     */
    private KeyPairInfoData getKeyPairInfo(final KeyIdentifier keyIdentifier) throws KeyIdentifierNotFoundException,
            KeyAccessProviderServiceException {

        try {
            final KeyPairInfoData keyPairInfoData = kapsExternalPersistenceManager.findEntityByKeyIdentifier(KeyPairInfoData.class,
                    keyIdentifier.getId(), KEY_IDENTIFIER_COLUMN);
            if (keyPairInfoData == null) {
                LOGGER.error("{} {}", ErrorMessages.KEYIDENTIFIER_NOT_FOUND, keyIdentifier);
                throw new KeyIdentifierNotFoundException(ErrorMessages.KEYIDENTIFIER_NOT_FOUND);
            }
            return keyPairInfoData;
        } catch (PersistenceException persistenceException) {
            LOGGER.error(ErrorMessages.UNABLE_TO_FETCH_KEYPAIR, persistenceException);
            throw new KeyAccessProviderServiceException(ErrorMessages.UNABLE_TO_FETCH_KEYPAIR, persistenceException);
        }
    }

    private KeyPairInfoData createKeyPairInfoData(final String algorithm, final int modulus, final KeyPair keyPair)
            throws KeyAccessProviderServiceException, KeyEncryptionException, NoSuchAlgorithmException {
        final byte[] encryptedPrivateKey = keyWrapUtils.encrypt(keyPair.getPrivate());

        final EncryptedPrivateKeyInfoData encryptedPrivateKeyInfoData = new EncryptedPrivateKeyInfoData();
        encryptedPrivateKeyInfoData.setPrivatekey(encryptedPrivateKey);
        encryptedPrivateKeyInfoData.setHashOfPrivateKey(HashGeneratorUtils.generateSHA256(encryptedPrivateKey));

        try {
            kapsExternalPersistenceManager.createEntity(encryptedPrivateKeyInfoData);
        } catch (PersistenceException persistenceException) {
            LOGGER.error(ErrorMessages.UNABLE_TO_SAVE_PRAVATE_KEY, persistenceException);
            throw new KeyAccessProviderServiceException(ErrorMessages.UNABLE_TO_SAVE_PRAVATE_KEY, persistenceException);
        }

        final KeyPairInfoData keyPairInfoData = new KeyPairInfoData();
        keyPairInfoData.setKeyIdentifier(getKeyIdentifierSequenceId());
        keyPairInfoData.setAlgorithm(algorithm);
        keyPairInfoData.setKeysize(modulus);
        keyPairInfoData.setKeyPairStatus(KeyPairStatus.ACTIVE.getId());
        keyPairInfoData.setPublickey(keyPair.getPublic().getEncoded());
        keyPairInfoData.setEncryptedprivatekeyinfo(encryptedPrivateKeyInfoData);

        if (keyPairInfoData.getCreatedtime() == null) {
            keyPairInfoData.setCreatedtime(new Date());
        }

        keyPairInfoData.setUpdatedtime(new Date());

        return keyPairInfoData;
    }

    private String getKeyIdentifierSequenceId() {
        final BigInteger seq = (BigInteger) (kapsExternalPersistenceManager.createNativeQuery("select nextval('SEQ_KEY_IDENTIFIER_ID')")).get(0);
        return String.format("K%020d", seq.longValue());
    }

}