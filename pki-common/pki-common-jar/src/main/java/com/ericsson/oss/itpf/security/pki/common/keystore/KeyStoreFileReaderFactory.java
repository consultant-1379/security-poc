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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.keystore.constants.KeyStoreErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.keystore.exception.KeyStoreFileReaderException;
import com.ericsson.oss.itpf.security.pki.common.keystore.exception.KeyStoreTypeNotSupportedException;

/**
 * This factory class is used to get the instance of KeyStoreFileReader using KeyStoreType which is present in KeyStoreInfo.
 * 
 * @author xjagcho
 * 
 */
public class KeyStoreFileReaderFactory {
    private KeyStoreFileReader keyStoreFileReader;

    private static final Logger logger = LoggerFactory.getLogger(KeyStoreFileReaderFactory.class);

    /**
     * This method is used to get the get the instance of KeyStoreFileReader based on the keyStoreType present in the KeyStoreInfo.
     * 
     * @param keyStoreInfo
     *            contains keyStoreType,password,filePath and aliasName
     * @return KeyStoreFileReader is the specific KeyStore instance.
     * @throws KeystoreFileReaderException
     *             if the KeyStoreType is wrong
     * 
     */
    public KeyStoreFileReader getKeystoreFileReaderInstance(final KeyStoreInfo keyStoreInfo) throws KeyStoreFileReaderException {
        logger.debug("Start of method getKeystoreFileReaderInstance of KeyStoreFileReaderFactory class");
        switch (keyStoreInfo.getKeyStoreType()) {
        case JKS:
        case PKCS12:
            keyStoreFileReader = new JksPkcs12KeyStoreFileReader();
            break;
        default:
            logger.error("KeyStore is not supported with type :{}", keyStoreInfo.getKeyStoreType());
            throw new KeyStoreTypeNotSupportedException(KeyStoreErrorMessages.UNSUPPORTED_KEY_STORE_TYPE);
        }
        logger.debug("End of method getKeystoreFileReaderInstance of KeyStoreFileReaderFactory class");
        return keyStoreFileReader;

    }

}
