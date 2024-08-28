/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.credmsapi.api.model;

import java.io.File;
import java.io.Serializable;

public class KeystoreInfo implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * KeystoreInfo represents a collection of informations related to the Key Store, at present the aggregated data are: file pathname, KeyStore Password and certificate type.
     */

    private String keyAndCertLocation; // single file for key and cert
    private String privateKeyLocation; // specific file for key only
                                       // (BASE64)
    private String certificateLocation; // specific file for cert only
                                        // (BASE64)

    private String keyStoreFolder; // folder to contain all files (e.g. Apache)

    private CertificateFormat certFormat;
    private String keyStorePwd; // password to store any file

    private String alias;

    /**
     * @param keyAndCertLocation
     * @param privateKeyLocation
     * @param certificateLocation
     * @param keyStoreFolder
     * @param certFormat
     * @param keyStorePwd
     * @param alias
     */
    public KeystoreInfo(final String keyAndCertLocation, final String privateKeyLocation, final String certificateLocation, final String keyStoreFolder, final CertificateFormat certFormat,
            final String keyStorePwd, final String alias) {

        super();
        this.keyAndCertLocation = keyAndCertLocation;
        this.privateKeyLocation = privateKeyLocation;
        this.certificateLocation = certificateLocation;
        this.keyStoreFolder = keyStoreFolder;
        this.certFormat = certFormat;
        this.keyStorePwd = keyStorePwd;
        this.alias = alias;
    }

    /**
     * @return the keyStorePwd
     */
    public String getKeyStorePwd() {
        return this.keyStorePwd;
    }

    /**
     * @param keyStorePwd
     *            the keyStorePwd to set
     */
    public void setKeyStorePwd(final String keyStorePwd) {
        this.keyStorePwd = keyStorePwd;
    }

    /**
     * @return the keyAndCertLocation
     */
    public String getKeyAndCertLocation() {
        return this.keyAndCertLocation;
    }

    /**
     * @param keyAndCertLocation
     *            the keyAndCertLocation to set
     */
    public void setKeyAndCertLocation(final String keyAndCertLocation) {
        this.keyAndCertLocation = keyAndCertLocation;
    }

    /**
     * @return the certFormat
     */
    public CertificateFormat getCertFormat() {
        return this.certFormat;
    }

    /**
     * @param certFormat
     *            the certFormat to set
     */
    public void setCertFormat(final CertificateFormat certFormat) {
        this.certFormat = certFormat;
    }

    /**
     * @return the alias
     */
    public String getAlias() {
        return this.alias;
    }

    /**
     * @param alias
     *            the alias to set
     */
    public void setAlias(final String alias) {
        this.alias = alias;
    }

    /**
     * @return the privateKeyLocation
     */
    public String getPrivateKeyLocation() {
        return this.privateKeyLocation;
    }

    /**
     * @param privateKeyLocation
     *            the privateKeyLocation to set
     */
    public void setPrivateKeyLocation(final String privateKeyLocation) {
        this.privateKeyLocation = privateKeyLocation;
    }

    /**
     * @return the certificateLocation
     */
    public String getCertificateLocation() {
        return this.certificateLocation;
    }

    /**
     * @param certificateLocation
     *            the certificateLocation to set
     */
    public void setCertificateLocation(final String certificateLocation) {
        this.certificateLocation = certificateLocation;
    }

    /**
     * @return the keyStoreFolder
     */
    public String getKeyStoreFolder() {
        return this.keyStoreFolder;
    }

    /**
     * @param keyStoreFolder
     *            the keyStoreFolder to set
     */
    public void setKeyStoreFolder(final String keyStoreFolder) {
        this.keyStoreFolder = keyStoreFolder;
    }

    /**
     * @param
     * 
     */
    public boolean isValid() {

        // Alias is supposed to be MANDATORY for all cases
        if (this.alias == null || this.alias.isEmpty()) {
            return false;
        }

        if (this.certFormat == null) {
            return false;
        }

        if (!this.isKeyStorePwdValid()) {
            return false;
        }

        if (!this.isKeyAndCertLocationValid()) {
            if (!this.isKeyStoreFolderValid()) {
                if (!this.isFileCoupleValid()) {
                    return false;
                }

                return (this.isFileCoupleAccessible()); // couple found!
            }
            if (this.isFileCoupleValid()) {
                return false;
            }
            return (this.isKeyStoreFolderAccessible()); // KeyStoreFolder found!
        }
        if (this.isKeyStoreFolderValid() || this.isFileCoupleValid()) {
            return false;
        }

        return (this.isKeyAndCertLocationAccessible()); // KeyAndCertLocation found!
    }

    /**
     * 
     * @return
     */
    public boolean isKeyAndCertLocationValid() {
        // one single file for both key and cert
        if (this.keyAndCertLocation == null || this.keyAndCertLocation.isEmpty()) {
            return false;
        }
        return true;
    }

    /**
     * 
     * @return
     */
    public boolean isKeyStoreFolderValid() {
        // one directory name to store multiple files
        if (this.keyStoreFolder == null || this.keyStoreFolder.isEmpty()) {
            return false;
        }
        return true;
    }

    /**
     * 
     * @return
     */
    public boolean isFileCoupleValid() {
        // a couple of files one for key and one for cert (for BASE64 only)
        if ((this.certificateLocation == null || this.certificateLocation.isEmpty()) || (this.privateKeyLocation == null || this.privateKeyLocation.isEmpty())) {
            return false;
        }

        // Following control to be checked
        if (!this.certFormat.equals(CertificateFormat.BASE_64)) {
            return false;
        }

        return true;
    }

    /**
     * 
     * @return
     */
    public boolean isKeyStorePwdValid() {

        if (this.keyStorePwd == null) {
            return false;
        }
        return true;
    }

    /**
     * 
     * @return
     */
    public boolean isKeyAndCertLocationAccessible() {
        return this.isFileAccessible(this.keyAndCertLocation);
    }

    /**
     * 
     * @return
     */
    public boolean isKeyStoreFolderAccessible() {
        return this.isFileAccessible(this.keyStoreFolder);
    }

    /**
     * 
     * @return
     */
    public boolean isFileCoupleAccessible() {
        return (this.isFileAccessible(this.certificateLocation) && this.isFileAccessible(this.privateKeyLocation));
    }

    /**
     * 
     * @param filePathName
     * @return
     */
    private boolean isFileAccessible(final String filePathName) {

        final File inputFile = new File(filePathName);

        final File parent = inputFile.getParentFile();

        if (parent == null || parent.getName().isEmpty()) {
            return true;
        }

        if (parent.exists() && parent.isDirectory() && parent.canWrite()) {
            return true;
        }

        return false;
    }

    /**
     * delete
     * 
     */
    public void delete() {

        if (this.isKeyStoreFolderValid()) {
            // delete file inside folder
            final File keyStorefolderFile = new File(this.keyStoreFolder);
            if (keyStorefolderFile.exists() && keyStorefolderFile.isDirectory()) {
                this.removeFolderEntries();
                // after files deletion, check if there are more files inside the directory
                final File[] filesAfter = keyStorefolderFile.listFiles();
                if (filesAfter.length == 0) {
                    // delete the entire directory
                    keyStorefolderFile.delete();
                }
            }
        }
        if (this.isFileCoupleValid()) {
            // delete keystore files
            final File privateKeyFile = new File(this.privateKeyLocation);
            if (privateKeyFile.exists()) {
                privateKeyFile.delete();
            }
            final File certificateFile = new File(this.certificateLocation);
            if (certificateFile.exists()) {
                certificateFile.delete();
            }
        }
        if (this.isKeyAndCertLocationValid()) {
            // delete key store files
            final File keyAndCertFile = new File(this.keyAndCertLocation);
            if (keyAndCertFile.exists()) {
                keyAndCertFile.delete();
            }
        }
    }

    /**
     * removeFolderEntries
     */
    public void removeFolderEntries() {

        if (this.isKeyStoreFolderValid()) {
            // delete file inside folder
            final File keyStorefolderFile = new File(this.keyStoreFolder);
            if (keyStorefolderFile.exists() && keyStorefolderFile.isDirectory()) {
                final File[] listOfFiles = keyStorefolderFile.listFiles();
                for (int i = 0; i < listOfFiles.length; i++) {
                    if (listOfFiles[i].isFile()) {
                        if ((this.alias != null) && (listOfFiles[i].getName().startsWith(this.alias))) {
                            listOfFiles[i].delete();
                        }
                    }
                }
            }
        }
    }

}
