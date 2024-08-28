/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2014
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmsapi.storage.business;

import java.io.*;
import java.security.*;
import java.security.cert.CRL;
import java.security.cert.Certificate;

import org.bouncycastle.openssl.PEMEncryptor;
import org.bouncycastle.openssl.jcajce.JcaPEMWriter;
import org.bouncycastle.openssl.jcajce.JcePEMEncryptorBuilder;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.ConfigurationException;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.ErrorMsg;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.PropertiesReader;
import com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialWriter;
import com.ericsson.oss.itpf.security.credmsapi.storage.exceptions.StorageException;

/**
 * 
 * @author ewagdeb
 * 
 */
public class Base64Writer implements CredentialWriter {
	
    private static final Logger LOG = LogManager.getLogger(Base64Writer.class);

    /**
     * 
     */
    //private static final org.slf4j.Logger LOG = LoggerFactory.getLogger(Base64Writer.class);

    /**
     * Truststore file Path
     */
    private String storeFolderPath = "";
    private String storeFilePath = "";

    /**
     * key password
     */

    private String password = "";

    /**
     * .CER file Path
     */
    private String cerFilePath = "";

    /**
     * .Key File Path
     */
    private String privateKeyFilePath = "";

    /**
     * EncryptionAlgorithm
     */
    // possible values are "DES-EDE"  "AES-128-CFB" "AES-256-CFB"
    private String encryptionAlgorithm;


    
    private Base64Writer() {

    }

    public Base64Writer(final String storeFolderPath, final String storeFilePath, final String cerFilePath, final String privateKeyFilePath, final String password)
            throws StorageException {
        this();
        this.storeFolderPath = storeFolderPath;
        this.storeFilePath = storeFilePath;
        this.cerFilePath = cerFilePath;
        this.privateKeyFilePath = privateKeyFilePath;
        if (password != null && !password.trim().equals("")) {
            this.password = password;
        }

        // read the encryption algorithm to use
        try {
            this.encryptionAlgorithm = PropertiesReader.getProperty(PropertiesReader.PEM_ENCRYPTION, PropertiesReader.PEM_ENCRYPTION_DEFAULT);
        } catch (final ConfigurationException ex) {
        	LOG.error(ErrorMsg.API_ERROR_STORAGE_READ_ENCRYPTALG,cerFilePath);
            throw new StorageException(ex);
        }

    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.nms.security.pki.store.CredentialWriter#storeKeyPair(java .security.Key, java.security.cert.Certificate, java.lang.String)
     */
    @Override
    public void storeKeyPair(final Key key, final Certificate[] certificateChain, final String alias) throws StorageException {

        // use these local variables not to risk to modify the global ones
        String myPrivateKeyFilePath = this.privateKeyFilePath;
        String myCerFilePath = this.cerFilePath;
        // trick if only one file is need
        if ((this.storeFilePath != null) && !("".equalsIgnoreCase(this.storeFilePath.trim()))) {
            myPrivateKeyFilePath = this.storeFilePath;
            myCerFilePath = this.storeFilePath;
        }
        
        System.out.println("storeKeyPair "+alias+" in "+myCerFilePath);
        LOG.debug("storeKeyPair "+alias+" in "+myCerFilePath);

        // Store away the .Key
        Writer fosKey = null;

        JcaPEMWriter pemKey = null;

        // Store away the .CER
        Writer fosCer = null;

        JcaPEMWriter pemCer = null;

        try {
            //            LOG.info(Logger.getLogMessage(Logger.LOG_INFO_CREATE_START_KEYSTORE), privateKeyfile + "\n" + cerFilePath);
            try {
                final File file = new File(myPrivateKeyFilePath);
                if (!file.exists()) {
                    file.createNewFile();
                }
            } catch (final Exception e) {
            	LOG.error(ErrorMsg.API_ERROR_STORAGE_CREATE_PKFILE,myPrivateKeyFilePath);
            }

            // writer for private key is always in overwrite mode, the "writeObject" will delete the previous content 
            fosKey = new FileWriter(new File(myPrivateKeyFilePath));
            pemKey = new JcaPEMWriter(fosKey);
            if (!this.password.trim().equals("")) {
                final JcePEMEncryptorBuilder builder = new JcePEMEncryptorBuilder(this.encryptionAlgorithm);
                builder.setProvider("BC");
                builder.setSecureRandom(new SecureRandom());
                final PEMEncryptor penc = builder.build(this.password.toCharArray());
                pemKey.writeObject(key, penc);
            } else {
                // Constructor for an unencrypted private key PEM object.
                final PrivateKey privKey = (PrivateKey) key;
                pemKey.writeObject(privKey);
            }

            pemKey.flush();
            // close to allow append
            fosKey.close();
            pemKey.close();

            try {
                final File file = new File(myCerFilePath);
                if (!file.exists()) {
                    file.createNewFile();
                }
            } catch (final Exception e) {
            	LOG.error(ErrorMsg.API_ERROR_STORAGE_CREATE_CERTFILE,myCerFilePath);
            }

            // append true allows the certificate to be added to the key file
            fosCer = new FileWriter(new File(myCerFilePath), true);
            pemCer = new JcaPEMWriter(fosCer);
            
            // write the certificate path (the chain)
            for (int i=0; i<certificateChain.length; i++) {
                pemCer.writeObject(certificateChain[i]);
            }
            pemCer.flush();

            //            LOG.info(Logger.getLogMessage(Logger.LOG_INFO_CREATE_END_KEYSTORE), "[" + privateKeyfile + "]["
            //                    + cerFilePath + "]");
            //            LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_CREATE_KEYSTORE), "[" + privateKeyfile + "][" + cerFilePath
            //                    + "]");
        } catch (final Exception ex) {
        	LOG.error(ErrorMsg.API_ERROR_STORAGE_WRITE_PKCERT,myPrivateKeyFilePath,myCerFilePath);
            //            LOG.error(Logger.getLogMessage(Logger.LOG_ERROR_CREATE_KEYSTORE), "[" + privateKeyfile + "][" + cerFilePath
            //                    + "]");
            try {
                final File file = new File(myPrivateKeyFilePath);
                final File file2 = new File(myCerFilePath);
                file.delete();
                file2.delete();
            } catch (final Exception ex1) {
            	LOG.error(ErrorMsg.API_ERROR_STORAGE_DELETE_PKCERT,myPrivateKeyFilePath,myCerFilePath);
            }
            throw new StorageException(ex);

        } finally {

            try {
                if (fosKey != null) {
                    fosKey.close();
                }
                if (fosCer != null) {
                    fosCer.close();
                }
                if (pemCer != null) {
                    pemCer.close();
                }
                if (pemKey != null) {
                    pemKey.close();
                }

            } catch (final Exception ex) {
            	LOG.error(ErrorMsg.API_ERROR_STORAGE_CLOSE_WRITERS);
            }

        }

    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.nms.security.pki.store.CredentialWriter#addTrustedEntry( java.security.cert.Certificate, java.lang.String)
     */
    @Override
    public void addTrustedEntry(final Certificate cert, final String alias) throws StorageException {

        // Store away the keystore.
        Writer fos = null;
        JcaPEMWriter pw = null;
        String myStoreFilePath = null;

        try {
            myStoreFilePath = this.folderManagement(alias, ".pem");
            
            System.out.println("addTrustedEntry "+alias+" in "+myStoreFilePath);
            LOG.debug("addTrustedEntry "+alias+" in "+myStoreFilePath);
            
            final File file = new File(myStoreFilePath);
            if (!file.exists()) {
                file.createNewFile();
            }
            fos = new FileWriter(new File(myStoreFilePath), true);
            pw = new JcaPEMWriter(fos);
            pw.writeObject(cert);
            pw.flush();

        } catch (final Exception ex) {
            LOG.error(ErrorMsg.API_ERROR_STORAGE_WRITE_KSFILE,myStoreFilePath);
            final File file = new File(myStoreFilePath);
            file.delete();
            throw new StorageException(ex);

        } finally {

            try {
                if (fos != null) {
                    fos.close();
                }

            } catch (final IOException ex) {
            	LOG.error(ErrorMsg.API_ERROR_STORAGE_CLOSE_WRITERS);
            }
            try {
                if (pw != null) {
                    pw.close();
                }

            } catch (final IOException ex) {
            	LOG.error(ErrorMsg.API_ERROR_STORAGE_CLOSE_WRITERS);
            }

        }

    }

    /**
     * storeCRL
     * 
     * @param crl
     * @throws StorageException
     */
    @Override
    public void addCrlEntry(final CRL crl, final String alias) throws StorageException {

        Writer fos = null;
        JcaPEMWriter pw = null;
        String myStoreFilePath = null;

        try {

            myStoreFilePath = this.folderManagement(alias, ".crl");
            
            System.out.println("addCrlEntry "+alias+" in "+myStoreFilePath);
            LOG.debug("addCrlEntry "+alias+" in "+myStoreFilePath);
            
            try {
                final File file = new File(myStoreFilePath);
                if (!file.exists()) {
                    file.createNewFile();
                }
            } catch (final Exception e) {
            	LOG.error(ErrorMsg.API_ERROR_STORAGE_CREATE_CRLFILE, myStoreFilePath);
            }

            fos = new FileWriter(new File(myStoreFilePath), true);
            pw = new JcaPEMWriter(fos);
            pw.writeObject(crl);
            pw.flush();
            pw.close();
        } catch (final IOException e) {
        	LOG.error(ErrorMsg.API_ERROR_STORAGE_WRITE_CRLFILE,myStoreFilePath);
            try {
                if (pw != null) {
                    pw.close();
                }
            } catch (final IOException e1) {
            	LOG.error(ErrorMsg.API_ERROR_STORAGE_CLOSE_WRITERS);
            }
            throw new StorageException(e);
        }
    }

    /**
     * @param alias
     * @param myStoreFilePath
     * @return
     */
    private String folderManagement(final String alias, final String fileExtension) {

        String myStoreFilePath = this.storeFilePath;
        // folder management
        if ((this.storeFolderPath != null) && (!"".equalsIgnoreCase(this.storeFolderPath))) {
            // check if the directory exists
            final File file = new File(this.storeFolderPath);
            if (!file.exists()) {
                file.mkdir();
            }
            // build the new filename
            myStoreFilePath = this.storeFolderPath + File.separator + alias + fileExtension;
        }
        //           LOG.info(Logger.getLogMessage(Logger.LOG_INFO_CREATE_START_TRUSTSTORE), storeFilePath);
        return myStoreFilePath;
    }
    

    /* (non-Javadoc)
     * @see com.ericsson.oss.itpf.security.credmsapi.storage.api.CredentialWriter#deleteEntry(java.lang.String)
     */
    @Override
    public void deleteEntry(final String alias) throws StorageException {
        
        // NO WAY; we have to delete the whole file
        if (this.storeFilePath != "") {
            final File file = new File(this.storeFilePath);
            if (file.exists()) {
                if (!file.delete()) {
                    throw new StorageException("Could not delete base64 file");
                }
            }
        }
    }


} // end of Base64Writer
