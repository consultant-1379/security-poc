package com.ericsson.oss.itpf.security.credmsapi.storage.business;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.business.utils.ErrorMsg;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialWriter;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.StorageConstants;
import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;

public class CredentialWriterFactory {

    private static final Logger LOG = LogManager.getLogger(CredentialWriterFactory.class);
	
    private CredentialWriter writer;

    /**
     * 
     * @param storeType
     * @param storeFilePath
     * @param password
     * @param overwritefile
     * @return CredentialWriter for the correspondent format
     * @throws StorageException
     */
    public CredentialWriter getCredentialwriterInstanceForCert(final String storeType, final String storeFilePath, final String password) throws StorageException {

        return this.getCredentialwriterInstanceForCert(storeType, storeFilePath, "", "", password);
    }

    /**
     * 
     * @param storeType
     * @param storeFilePath
     * @param certificateFileLocation
     * @param privateKeyLocation
     * @param password
     * @param overwritefile
     * @return CredentialWriter for the correspondent format
     * @throws StorageException
     */
    public CredentialWriter getCredentialwriterInstanceForCert(final String storeType, final String storeFilePath, final String certificateFileLocation, final String privateKeyLocation,
            final String password) throws StorageException {

        return this.getCredentialwriterInstance(storeType, "", storeFilePath, certificateFileLocation, privateKeyLocation, password);
    }

    /**
     * 
     * @param storeType
     * @param storeFolderPath
     * @param storeFilePath
     * @param password
     * @param overwritefile
     * @return @return CredentialWriter for the correspondent format
     * @throws StorageException
     */

    public CredentialWriter getCredentialwriterInstanceForTrust(final String storeType, final String storeFilePath, final String password) throws StorageException {

        return this.getCredentialwriterInstanceForTrust(storeType, "", storeFilePath, password);

    }

    /**
     * 
     * @param storeType
     * @param storeFolderPath
     * @param storeFilePath
     * @param password
     * @param overwritefile
     * @return @return CredentialWriter for the correspondent format
     * @throws StorageException
     */

    public CredentialWriter getCredentialwriterInstanceForTrust(final String storeType, final String storeFolderPath, final String storeFilePath, final String password)
            throws StorageException {

        return this.getCredentialwriterInstance(storeType, storeFolderPath, storeFilePath, "", "", password);

    }

    /**
     * 
     * @param storeType
     * @param storeFolderPath
     * @param storeFilePath
     * @param append
     * @return
     * @throws StorageException
     */
    public CredentialWriter getCredentialwriterInstanceForCRL(final String storeType, final String storeFolderPath, final String storeFilePath) throws StorageException {

        if (!StorageConstants.BASE64_PEM_STORE_TYPE.equals(storeType)) {
        	LOG.error(ErrorMsg.API_ERROR_STORAGE_CHECK_CRLSTORETYPE,storeType);
            throw new StorageException("CRL store is not supported with type : " + storeType);
        }
        return this.getCredentialwriterInstance(StorageConstants.BASE64_PEM_STORE_TYPE, storeFolderPath, storeFilePath, "", "", "");
    }

    /**
     * 
     * getCredentialwriterInstance
     * 
     * @param storeType
     * @param storeFolderPath
     * @param storeFilePath
     * @param certificateFileLocation
     * @param privateKeyLocation
     * @param password
     * @param append
     * @return CredentialWriter for the correspondent format
     * @throws StorageException
     */
    private CredentialWriter getCredentialwriterInstance(final String storeType, final String storeFolderPath, final String storeFilePath, final String certificateFileLocation,
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

            this.writer = new JKSWriter(storeFolderPath, storeFilePath, password, StorageConstants.JKS_STORE_TYPE);

        } else if (StorageConstants.JCEKS_STORE_TYPE.equalsIgnoreCase(storeType)) {

            this.writer = new JKSWriter(storeFolderPath, storeFilePath, password, StorageConstants.JCEKS_STORE_TYPE);

        } else if (StorageConstants.PKCS12_STORE_TYPE.equalsIgnoreCase(storeType)) {

            this.writer = new PKCS12Writer(storeFolderPath, storeFilePath, password);

        } else if (StorageConstants.BASE64_PEM_STORE_TYPE.equalsIgnoreCase(storeType)) {

            this.writer = new Base64Writer(storeFolderPath, storeFilePath, certificateFileLocation, privateKeyLocation, password);
            
        } else if (StorageConstants.LEGACY_XML_STORE_TYPE.equalsIgnoreCase(storeType)) {

            this.writer = new LegacyXMLWriter(storeFilePath, password);
        } else {
        	LOG.error(ErrorMsg.API_ERROR_STORAGE_CHECK_UNSUPPSTORETYPE,storeType);
            throw new StorageException("Credential store is not supported with type : " + storeType);
        }

        return this.writer;
    }

} // end of CredentialWriterFactory

