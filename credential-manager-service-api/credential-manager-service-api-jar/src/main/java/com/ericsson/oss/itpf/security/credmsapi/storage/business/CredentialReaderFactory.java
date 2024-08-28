package com.ericsson.oss.itpf.security.credmsapi.storage.business;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.business.utils.ErrorMsg;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialReader;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.StorageConstants;
import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;

public class CredentialReaderFactory {

    private static final Logger LOG = LogManager.getLogger(CredentialReaderFactory.class);

    private CredentialReader reader;

    /**
     * 
     * @param storeType
     * @param storeFilePath
     * @param password
     * @param overwritefile
     * @return CredentialWriter for the correspondent format
     * @throws StorageException
     */
    public CredentialReader getCredentialreaderInstance(final String storeType, final String storeFilePath, final String password) throws StorageException {

        return this.getCredentialreaderInstance(storeType, "", storeFilePath, "", "", password);
    }

    /**
     * 
     * @param storeType
     * @param storeFilePath
     * @param password
     * @param overwritefile
     * @return CredentialWriter for the correspondent format
     * @throws StorageException
     */
    public CredentialReader getCredentialreaderInstance(final String storeType, final String storeFolderPath, final String storeFilePath, final String password) throws StorageException {

        return this.getCredentialreaderInstance(storeType, storeFolderPath
                , storeFilePath, "", "", password);
    }
    
    /**
     * 
     * @param storeType
     * @param storeFolderPath
     * @param storeFilePath
     * @param certificateFileLocation
     * @param privateKeyLocation
     * @param password
     * @param overwritefile
     * @return CredentialWriter for the correspondent format
     * @throws StorageException
     */
    private CredentialReader getCredentialreaderInstance(final String storeType, final String storeFolderPath, final String storeFilePath, final String certificateFileLocation,
            final String privateKeyLocation, final String password) throws StorageException {

        if (storeType == null || "".equalsIgnoreCase(storeType.trim())) {
        	LOG.error(ErrorMsg.API_ERROR_STORAGE_CHECK_STORETYPE,storeType);
            throw new StorageException("Invalid credential store type" + storeType);
        }

        if ((storeFolderPath == null || "".equalsIgnoreCase(storeFolderPath.trim())) && (storeFilePath == null || "".equalsIgnoreCase(storeFilePath.trim()))
                && (privateKeyLocation == null || "".equalsIgnoreCase(privateKeyLocation.trim()))) {
            LOG.error(ErrorMsg.API_ERROR_STORAGE_CHECK_STOREPATH,storeFilePath);
            throw new StorageException("Invalid credential store file path");
        }

        if (StorageConstants.JKS_STORE_TYPE.equalsIgnoreCase(storeType)) {

            this.reader = new JKSReader(storeFolderPath, storeFilePath, password, StorageConstants.JKS_STORE_TYPE);

        } else if (StorageConstants.JCEKS_STORE_TYPE.equalsIgnoreCase(storeType)) {

            this.reader = new JKSReader(storeFolderPath, storeFilePath, password, StorageConstants.JCEKS_STORE_TYPE);

        } else if (StorageConstants.PKCS12_STORE_TYPE.equalsIgnoreCase(storeType)) {

            this.reader = new PKCS12Reader(storeFolderPath, storeFilePath, password, StorageConstants.PKCS12_STORE_TYPE);

        } else if (StorageConstants.BASE64_PEM_STORE_TYPE.equalsIgnoreCase(storeType)) {

            this.reader = new Base64Reader(storeFolderPath, storeFilePath, certificateFileLocation, privateKeyLocation, password);
            
        } else if (StorageConstants.LEGACY_XML_STORE_TYPE.equalsIgnoreCase(storeType)) {

            this.reader = new LegacyXMLReader(storeFilePath, password);
            
        } else {
        	LOG.error(ErrorMsg.API_ERROR_STORAGE_CHECK_UNSUPPSTORETYPE,storeType);
            throw new StorageException("Credential store is not supported with type : " + storeType);
        }

        return this.reader;
    }

}
