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

import java.security.NoSuchAlgorithmException;
import java.security.Security;
import java.util.Collections;
import java.util.List;

import javax.crypto.*;
import javax.crypto.spec.SecretKeySpec;
import javax.inject.Inject;
import javax.persistence.PersistenceException;
import javax.persistence.Query;

import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.kaps.common.Constants;
import com.ericsson.oss.itpf.security.kaps.common.ErrorMessages;
import com.ericsson.oss.itpf.security.kaps.common.exception.SymmetricKeyGenerationException;
import com.ericsson.oss.itpf.security.kaps.common.persistence.KAPSInternalPersistenceManager;
import com.ericsson.oss.itpf.security.kaps.common.persistence.entity.SymmetricKeyData;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.pki.common.util.ValidationUtils;

/**
 * Handler class to do the DB operations related to key management.
 * 
 */
public class SymmetricKeyPersistenceHandler {

    private static final Logger LOGGER = LoggerFactory.getLogger(SymmetricKeyPersistenceHandler.class);
    private static final String REMOVE_UNUSED_SYMMETRICKEYDATA = "delete from SymmetricKeyData s where s.id not in (select sd.id from SymmetricKeyData sd where sd.id=:id)";

    @Inject
    KAPSInternalPersistenceManager kapsInternalPersistenceManager;

    static {
        try {
            if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
                Security.addProvider(new BouncyCastleProvider());
            }
        } catch (SecurityException securityException) {
            LOGGER.error("Cannot register BouncyCastleProvider", securityException);
        }
    }

    /**
     * Fetch and generate Symmetric key
     * 
     * @return symmetric key from DB
     * @throws KeyAccessProviderServiceException
     *             Thrown to indicate any internal database errors
     */
    public SecretKey fetchOrGenerateSecretKey() throws KeyAccessProviderServiceException {
        SecretKey secretKey = null;

        final List<SymmetricKeyData> symmetricKeyDatas = getSymmetricKeyData();

        if (ValidationUtils.isNullOrEmpty(symmetricKeyDatas)) {
            generateAndSaveSymmetricKey();
        }

        secretKey = getSymmetricKey();

        return secretKey;
    }

    private void generateAndSaveSymmetricKey() throws KeyAccessProviderServiceException, SymmetricKeyGenerationException {
        final SecretKey secretKey = generateSymmetricKey(Constants.SYMMETRIC_KEY_ALGORITHM, getSymmetricKeySize());
        saveSymmetricKey(secretKey);
    }

    private SecretKey generateSymmetricKey(final String algorithm, final int modulus) throws SymmetricKeyGenerationException {
        SecretKey secretKey;

        try {
            final KeyGenerator keyGen = KeyGenerator.getInstance(algorithm);
            keyGen.init(modulus);

            secretKey = keyGen.generateKey();
        } catch (NoSuchAlgorithmException noSuchAlgorithmException) {
            LOGGER.error(ErrorMessages.UNABLE_GENERATE_SECRET_KEY, noSuchAlgorithmException);
            throw new SymmetricKeyGenerationException(ErrorMessages.UNABLE_GENERATE_SECRET_KEY, noSuchAlgorithmException);
        }

        return secretKey;
    }

    private SymmetricKeyData saveSymmetricKey(final SecretKey secretKey) throws KeyAccessProviderServiceException {
        final SymmetricKeyData symmetricKeyData = new SymmetricKeyData();
        symmetricKeyData.setSymmetricKey(secretKey.getEncoded());

        try {
            kapsInternalPersistenceManager.createEntity(symmetricKeyData);
        } catch (PersistenceException persistenceException) {
            LOGGER.error(ErrorMessages.UNABLE_GENERATE_SECRET_KEY, persistenceException);
            throw new KeyAccessProviderServiceException(ErrorMessages.UNABLE_GENERATE_SECRET_KEY);
        }

        return symmetricKeyData;
    }

    private SecretKey getSymmetricKey() throws KeyAccessProviderServiceException {
        final List<SymmetricKeyData> symmetricKeyDatas = getSymmetricKeyData();

        if (ValidationUtils.isNullOrEmpty(symmetricKeyDatas)) {
            LOGGER.error(ErrorMessages.UNABLE_TO_GET_SECRETKEY);
            throw new KeyAccessProviderServiceException(ErrorMessages.UNABLE_TO_GET_SECRETKEY);
        }

        final SymmetricKeyData symmetricKeyData = Collections.min(symmetricKeyDatas, new SymmetricKeyDataComparator());

        if (symmetricKeyDatas.size() > 1) {
            removeUnUsedSymmetricKeyData(symmetricKeyData.getId());
        }

        final SecretKey secretKey = convert(symmetricKeyData);

        return secretKey;
    }

    private List<SymmetricKeyData> getSymmetricKeyData() throws KeyAccessProviderServiceException {
        try {
            final List<SymmetricKeyData> resultList = kapsInternalPersistenceManager.findEntityByQuery(SymmetricKeyData.class);
            return resultList;
        } catch (PersistenceException exception) {
            LOGGER.error(ErrorMessages.UNABLE_TO_GET_SECRETKEY);
            throw new KeyAccessProviderServiceException(ErrorMessages.UNABLE_TO_GET_SECRETKEY, exception);
        }

    }

    private SecretKey convert(final SymmetricKeyData symmetricKeyData) throws KeyAccessProviderServiceException {
        SecretKey secretKey;

        try {
            final byte[] decodedKey = symmetricKeyData.getSymmetricKey();
            secretKey = new SecretKeySpec(decodedKey, Constants.SYMMETRIC_KEY_ALGORITHM);
        } catch (Exception exception) {
            LOGGER.error(exception.getMessage(), exception);
            throw new KeyAccessProviderServiceException(exception.getMessage(), exception);
        }

        return secretKey;
    }

    private int getSymmetricKeySize() {
        int supportedSymmetricKeySize = 128;

        try {
            if (Cipher.getMaxAllowedKeyLength(Constants.SYMMETRIC_KEY_ALGORITHM) >= 256) {
                supportedSymmetricKeySize = 256;
            }
        } catch (Exception exception) {
            LOGGER.debug("Unable to fetch max allowed keylength for AES", exception);
        }

        LOGGER.debug("symmetric generated with ::  {} ", supportedSymmetricKeySize);
        return supportedSymmetricKeySize;
    }

    private void removeUnUsedSymmetricKeyData(final long symmetricKeyDataId) throws KeyAccessProviderServiceException {
        try {
            final Query query = kapsInternalPersistenceManager.getEntityManager().createQuery(REMOVE_UNUSED_SYMMETRICKEYDATA);
            query.setParameter("id", symmetricKeyDataId).executeUpdate();

            LOGGER.warn("Either more symmetric keys exists in database and removing that unused symmetric keys from DB");
        } catch (PersistenceException persistenceException) {
            LOGGER.error(ErrorMessages.UNABLE_TO_REMOVE_UNUSED_SECRETKEY, persistenceException);
            throw new KeyAccessProviderServiceException(ErrorMessages.UNABLE_TO_REMOVE_UNUSED_SECRETKEY, persistenceException);
        }
    }
}