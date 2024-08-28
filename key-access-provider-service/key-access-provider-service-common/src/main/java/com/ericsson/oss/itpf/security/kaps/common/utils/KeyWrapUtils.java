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
package com.ericsson.oss.itpf.security.kaps.common.utils;

import java.security.*;

import javax.crypto.*;
import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.kaps.common.Constants;
import com.ericsson.oss.itpf.security.kaps.common.ErrorMessages;
import com.ericsson.oss.itpf.security.kaps.common.exception.KeyDecryptionException;
import com.ericsson.oss.itpf.security.kaps.common.exception.KeyEncryptionException;
import com.ericsson.oss.itpf.security.kaps.common.generator.SymmetricKeyGenerator;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;

//TODO to be moved to pki-common repo. User story ref : TORF-57836
/**
 * Class which will do all encryption and decryption of key related operations.
 *
 */
public class KeyWrapUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(KeyWrapUtils.class);

    @Inject
    SymmetricKeyGenerator symmetricGenerator;

    /**
     * wrap {@link PrivateKey} Object with secretKey.
     *
     * @param privateKey
     *            {@link PrivateKey} of {@link KeyPair} object
     * @return wrappedKey
     * @throws KeyAccessProviderServiceException
     *             Thrown to indicate any internal database errors
     * @throws KeyEncryptionException
     *             is thrown if any failures while encrypting private key.
     */
    public byte[] encrypt(final PrivateKey privateKey) throws KeyAccessProviderServiceException, KeyEncryptionException {
        final SecretKey secretKey = symmetricGenerator.getSecretKey();

        try {
            final Cipher cipher = Cipher.getInstance(Constants.WRAP_UNWRAP_PRIVATE_KEY_ALGORITHM);
            cipher.init(Cipher.WRAP_MODE, secretKey);

            final byte[] wrappedKey = cipher.wrap(privateKey);
            return wrappedKey;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException exception) {
            LOGGER.error(ErrorMessages.UNABLE_TO_ENCRYPT, exception);
            throw new KeyEncryptionException(ErrorMessages.UNABLE_TO_ENCRYPT, exception);
        }
    }

    /**
     * unwrap encryptedPrivateKey into {@link PrivateKey} Object with secretKey.
     *
     * @param encryptedPrivateKey
     *            encrypted private key
     * @param keyGenerationAlgorithm
     *            keyGenerationAlgorithm name
     * @return {@link PrivateKey} object
     *
     * @throws KeyDecryptionException
     *             is thrown if any failures while decrypting private key.
     * @throws KeyAccessProviderServiceException
     *             Thrown to indicate any internal database errors
     */
    public PrivateKey decrypt(final byte[] encryptedPrivateKey, final String keyGenerationAlgorithm) throws KeyAccessProviderServiceException, KeyDecryptionException {
        final SecretKey secretKey = symmetricGenerator.getSecretKey();

        try {
            final Cipher cipher = Cipher.getInstance(Constants.WRAP_UNWRAP_PRIVATE_KEY_ALGORITHM);
            cipher.init(Cipher.UNWRAP_MODE, secretKey);

            final PrivateKey privateKey = (PrivateKey) cipher.unwrap(encryptedPrivateKey, keyGenerationAlgorithm, Cipher.PRIVATE_KEY);
            return privateKey;
        } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException exception) {
            LOGGER.error(ErrorMessages.UNABLE_TO_DECRYPT, exception);
            throw new KeyDecryptionException(ErrorMessages.UNABLE_TO_DECRYPT, exception);
        }
    }
}
