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
package com.ericsson.oss.itpf.security.pki.common.keystore;

import javax.inject.Inject;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.keystore.constants.KeyStoreErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.keystore.exception.KeyStoreTypeNotSupportedException;

/**
 * This factory class is used to get the instance of KeyStoreFileWriter using KeyStoreType which is present in KeyStoreInfo.
 * 
 * @author xpranma
 * 
 */
public class KeyStoreFileWriterFactory {

    @Inject
    JksPkcs12KeyStoreFileWriter jksPkcs12KeyStoreFileWriter;

    @Inject
    PEMFileWriter pEMFileWriter;

    private static final Logger logger = LoggerFactory.getLogger(KeyStoreFileWriterFactory.class);

    /**
     * This method is used to get the get the instance of KeyStoreFileWriter based on the keyStoreType present in the KeyStoreInfo.
     * 
     * @param keyStoreInfo
     *            contains keyStoreType,password,filePath and aliasName
     * @return KeyStoreFileWriter is the specific KeyStore instance.
     * @throws KeyStoreTypeNotSupportedException
     *             if the KeyStoreType is wrong
     * 
     */
    public KeyStoreFileWriter getKeystoreFileWriterInstance(final KeyStoreInfo keyStoreInfo) throws KeyStoreTypeNotSupportedException {
        logger.debug("Start of method getKeystoreFileWriterInstance of KeyStoreFileWriterFactory class");
        switch (keyStoreInfo.getKeyStoreType()) {
        case JKS:
        case PKCS12:
            return jksPkcs12KeyStoreFileWriter;

        case PEM:
            return pEMFileWriter;

        default:
            logger.error("KeyStore is not supported with type :{}", keyStoreInfo.getKeyStoreType());
            throw new KeyStoreTypeNotSupportedException(KeyStoreErrorMessages.UNSUPPORTED_KEY_STORE_TYPE);
        }

    }

}
