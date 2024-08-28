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

public class TrustStoreInfo implements Serializable {

    private static final long serialVersionUID = 1L;

    /**
     * TruststoreInfo represents a collection of informations related to the Trust Store, at present the aggregated data are: file trustFileLocation, TrustStore Password and the type.
     */

    private String trustFileLocation;
    private String trustFolder;

    private TrustFormat trustFormat;
    private String trustStorePwd;
    private String alias;

    private TrustSource trustSource;

    /**
     * @param trustFileLocation
     * @param trustFolder
     * @param trustFormat
     * @param trustStorePwd
     * @param alias
     * @param trustSource
     */
    public TrustStoreInfo(final String trustFileLocation, final String trustFolder, final TrustFormat trustFormat, final String trustStorePwd, final String alias, final TrustSource trustSource) {
        super();
        this.trustFileLocation = trustFileLocation;
        this.trustFolder = trustFolder;
        this.trustFormat = trustFormat;
        this.trustStorePwd = trustStorePwd;
        this.alias = alias;
        this.trustSource = trustSource;
    }

    /**
     * @return the trustFileLocation
     */
    public String getTrustFileLocation() {
        return this.trustFileLocation;
    }

    /**
     * @param trustFileLocation
     *            the trustFileLocation to set
     */
    public void setTrustFileLocation(final String trustFileLocation) {
        this.trustFileLocation = trustFileLocation;
    }

    /**
     * @return the certFormat
     */
    public TrustFormat getCertFormat() {
        return this.trustFormat;
    }

    /**
     * @param certFormat
     *            the certFormat to set
     */
    public void setCertFormat(final TrustFormat certFormat) {
        this.trustFormat = certFormat;
    }

    /**
     * @return the trustStorePwd
     */
    public String getTrustStorePwd() {
        return this.trustStorePwd;
    }

    /**
     * @param trustStorePwd
     *            the trustStorePwd to set
     */
    public void setTrustStorePwd(final String trustStorePwd) {
        this.trustStorePwd = trustStorePwd;
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
     * @return the trustFolder
     */
    public String getTrustFolder() {
        return this.trustFolder;
    }

    /**
     * @param trustFolder
     *            the trustFolder to set
     */
    public void setTrustFolder(final String trustFolder) {
        this.trustFolder = trustFolder;
    }

    /**
     * @return the trustSource
     */
    public TrustSource getTrustSource() {
        return this.trustSource;
    }

    /**
     * @param trustSource
     *            the trustSource to set
     */
    public void setTrustSource(final TrustSource trustSource) {
        this.trustSource = trustSource;
    }

    /**
     * @return
     */
    public boolean isTrustSourceInternal() {
        if (this.getTrustSource() == TrustSource.INTERNAL) {
            return true;
        }
        return false;
    }

    /**
     * @return
     */
    public boolean isTrustSourceExternal() {
        if (this.getTrustSource() == TrustSource.EXTERNAL) {
            return true;
        }
        return false;
    }

    /**
     * @return
     */
    public boolean isTrustSourceInternalAndExternal() {
        if (this.getTrustSource() == TrustSource.BOTH) {
            return true;
        }
        return false;
    }

    /**
     * @param
     * 
     */
    public boolean isValid() {

        if (this.alias == null || this.alias.isEmpty()) {
            return false;
        }

        if (this.trustFormat == null) {
            return false;
        }

        if (!this.isTrustStorePwdValid()) {
            return false;
        }

        if (!this.isTrustFileLocationValid()) {
            if (!this.isTrustFolderValid()) {
                return false;
            }
            return this.isTrustFolderAccessible(); // folder found!
        }

        if (this.isTrustFolderValid()) {
            return false;
        }

        return this.isTrustFileLocationAccessible(); // trustFile found!
    }

    /**
     * isTrustFileLocationValid
     * 
     * @return boolean
     */
    public boolean isTrustFileLocationValid() {
        // one single file for trust
        if (this.trustFileLocation == null || this.trustFileLocation.isEmpty()) {
            return false;
        }
        return true;
    }

    /**
     * isTrustFolderValid
     * 
     * @return boolean
     */
    public boolean isTrustFolderValid() {
        // one directory name to store multiple files
        if (this.trustFolder == null || this.trustFolder.isEmpty()) {
            return false;
        }
        return true;
    }

    /**
     * isTrustStorePwdValid
     * 
     * @return boolean
     */
    public boolean isTrustStorePwdValid() {

        if (this.trustStorePwd == null) {
            return false;
        }
        return true;
    }

    public boolean isTrustFileLocationAccessible() {
        return this.isFileAccessible(this.trustFileLocation);
    }

    public boolean isTrustFolderAccessible() {
        return this.isFileAccessible(this.trustFolder);
    }

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

        if (this.isTrustFolderValid()) {
            // delete file inside folder
            final File trustStorefolderFile = new File(this.trustFolder);
            if (trustStorefolderFile.exists() && trustStorefolderFile.isDirectory()) {
                this.removeFolderEntries();
                // after files deletion, check if there are more files inside the directory
                final File[] filesAfter = trustStorefolderFile.listFiles();
                if (filesAfter.length == 0) {
                    // delete the entire directory
                    trustStorefolderFile.delete();
                }
            }
        }

        if (this.isTrustFileLocationValid()) {
            // delete store files
            final File trustFile = new File(this.trustFileLocation);
            if (trustFile.exists()) {
                trustFile.delete();
            }
        }
    }

    /**
     * removeFolderEntries
     */
    public void removeFolderEntries() {

        if (this.isTrustFolderValid()) {
            // delete file inside folder
            final File trustStorefolderFile = new File(this.trustFolder);
            if (trustStorefolderFile.exists() && trustStorefolderFile.isDirectory()) {
                final File[] listOfFiles = trustStorefolderFile.listFiles();
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
    
    @Override
    public  String toString() {
    
    	return "TrustFileLocation " + trustFileLocation + "TrustFileLocation " +trustFileLocation 
    			+ "\ntrustFolder " + trustFolder + "trustStorePwd " + trustStorePwd + "alias " + alias + 
    			"TrustFormat" +trustFormat.toString() + " trustSource" + trustSource.toString(); 

    	
    }

} // end of file
