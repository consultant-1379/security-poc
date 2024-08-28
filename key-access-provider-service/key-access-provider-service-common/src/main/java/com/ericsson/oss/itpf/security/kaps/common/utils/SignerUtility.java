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

import java.security.PrivateKey;

import javax.inject.Inject;

import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.kaps.common.ErrorMessages;
import com.ericsson.oss.itpf.security.kaps.common.exception.SignatureException;
import com.ericsson.oss.itpf.security.kaps.common.persistence.handler.KeyPairPersistenceHandler;
import com.ericsson.oss.itpf.security.kaps.exception.KeyAccessProviderServiceException;
import com.ericsson.oss.itpf.security.kaps.keypair.exception.KeyIdentifierNotFoundException;
import com.ericsson.oss.itpf.security.kaps.model.KeyIdentifier;

/**
 * Util class which provides operations related to signing.
 */
public class SignerUtility {

    private static final Logger LOGGER = LoggerFactory.getLogger(SignerUtility.class);
    
    @Inject
    private KeyPairPersistenceHandler keyPairPersistenceHandler;
    
    /**
     * It gets the private key from given key identifier and signs the content using given signature algorithm.
     * 
     * @param keyIdentifier
     *            key identifier of the private key
     * @param signatureAlgorithm
     *            algorithm used to sign the content.
     * @return Content Signer object
     * @throws KeyAccessProviderServiceException
     *             Thrown in case any problem with private key used to sign.
     * @throws KeyIdentifierNotFoundException
     *             Thrown in case given key identifier not found in kaps database.
     * @throws SignatureException
     *             Thrown in case signing is failed.
     */
    public ContentSigner getContentSigner(final KeyIdentifier keyIdentifier, final String signatureAlgorithm) throws KeyAccessProviderServiceException, KeyIdentifierNotFoundException,
            SignatureException {

        try {
            final PrivateKey privateKey = keyPairPersistenceHandler.getPrivateKey(keyIdentifier);
            final ContentSigner contentSigner = new JcaContentSignerBuilder(signatureAlgorithm).build(privateKey);
            return contentSigner;
        } catch (OperatorCreationException operatorCreationException) {
            LOGGER.error(ErrorMessages.SIGNATURE_GENERATION_FAILED, operatorCreationException.getMessage());
            throw new SignatureException(operatorCreationException);
        }
    }
}
