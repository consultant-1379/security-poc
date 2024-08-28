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
package com.ericsson.oss.itpf.security.credentialmanager.cli.model;

import java.io.File;

import com.ericsson.oss.itpf.security.credentialmanager.cli.exception.CredentialManagerException;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.CrlStoreType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.TrustStoreType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerTrustStore;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.SourceConstants;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.StoreConstants;

/**
 * 
 * Hold the Trust Store that comes from XMLBeans generated based on the XSD for credential manager
 * 
 */
public class CredentialManagerTrustStoreImpl implements CredentialManagerTrustStore {

    /**
     * 
     */
    private static final long serialVersionUID = 7976930869326287998L;
    private String location = "";
    private String password = "";
    private String type;
    private String folder = "";
    private String alias = "";
    private String source = "";


    /**
     * 
     * @param trustStoreObj
     */
    public CredentialManagerTrustStoreImpl(final Object storeObj) {

        if (storeObj != null && storeObj instanceof TrustStoreType) {

            // TrustSTore

            final TrustStoreType trustStore = (TrustStoreType) storeObj;

            this.setJKSFormat(trustStore);
            this.setJCEKSFormat(trustStore);
            this.setPKSC12Format(trustStore);
            this.setBASE64Format(trustStore);

            this.setSource(SourceConstants.TRUST_SOURCE_BOTH);
            if (trustStore.getTrustsource() != null) {
                this.setSource(trustStore.getTrustsource().value());
            }

            // check length of password
            if (!this.isValidPassword()) {
                throw new CredentialManagerException("trust store password must be at least 6 characters [Failed]");
            }

        } else if (storeObj != null && storeObj instanceof CrlStoreType) {

            // CRLStore

            final CrlStoreType crlStore = (CrlStoreType) storeObj;

            this.setBASE64Format(crlStore);

            this.setSource(SourceConstants.CRL_SOURCE_BOTH);
            if(crlStore.getCrlsource() != null){
                this.setSource(crlStore.getCrlsource().value());
            }
                

        } else {
            throw new CredentialManagerException("Loading information of trust store...[Failed]");
        }
    }


    /**
     * @param trustStore
     */
    private void setBASE64Format(final TrustStoreType trustStore) {
        if (trustStore.getBase64Truststore() != null) {
            if (trustStore.getBase64Truststore().getStorealias() != null) {
                this.setAlias(trustStore.getBase64Truststore().getStorealias());
            }

            if (trustStore.getBase64Truststore().getStorelocation() != null) {
                this.setLocation(trustStore.getBase64Truststore().getStorelocation());
            }

            if (trustStore.getBase64Truststore().getStorefolder() != null) {
                this.setFolder(trustStore.getBase64Truststore().getStorefolder());
            }

            if (trustStore.getBase64Truststore().getStorepassword() != null) {
                this.setPassword(trustStore.getBase64Truststore().getStorepassword().trim());
            }

            this.setType(StoreConstants.BASE64_STORE_TYPE);

        }
    }

    /**
     * @param crlStore
     */
    private void setBASE64Format(final CrlStoreType crlStore) {
        if (crlStore.getBase64Crlstore() != null) {
            if (crlStore.getBase64Crlstore().getStorealias() != null) {
                this.setAlias(crlStore.getBase64Crlstore().getStorealias());
            }

            if (crlStore.getBase64Crlstore().getStorelocation() != null) {
                this.setLocation(crlStore.getBase64Crlstore().getStorelocation());
            }

            if (crlStore.getBase64Crlstore().getStorefolder() != null) {
                this.setFolder(crlStore.getBase64Crlstore().getStorefolder());
            }

            this.setPassword("");

            this.setType(StoreConstants.BASE64_STORE_TYPE);
        }
    }

    /**
     * @param trustStore
     */
    private void setPKSC12Format(final TrustStoreType trustStore) {
        if (!(trustStore.getPkcs12Truststore() == null)) {
            if (trustStore.getPkcs12Truststore().getStorealias() != null) {
                this.setAlias(trustStore.getPkcs12Truststore().getStorealias().trim());
            }

            if (trustStore.getPkcs12Truststore().getStorelocation() != null) {
                this.setLocation(trustStore.getPkcs12Truststore().getStorelocation().trim());
            }

            if (trustStore.getPkcs12Truststore().getStorefolder() != null) {
                this.setFolder(trustStore.getPkcs12Truststore().getStorefolder().trim());
            }

            if (trustStore.getPkcs12Truststore().getStorepassword() != null) {
                this.setPassword(trustStore.getPkcs12Truststore().getStorepassword().trim());
            }

            this.setType(StoreConstants.PKCS12_STORE_TYPE);

        }
    }

    /**
     * @param trustStore
     */
    private void setJKSFormat(final TrustStoreType trustStore) {
        if (trustStore.getJkstruststore() != null) {
            if (trustStore.getJkstruststore().getStorealias() != null) {
                this.setAlias(trustStore.getJkstruststore().getStorealias().trim());
            }

            if (trustStore.getJkstruststore().getStorelocation() != null) {
                this.setLocation(trustStore.getJkstruststore().getStorelocation().trim());
            }

            if (trustStore.getJkstruststore().getStorefolder() != null) {
                this.setFolder(trustStore.getJkstruststore().getStorefolder().trim());
            }

            if (trustStore.getJkstruststore().getStorepassword() != null) {
                this.setPassword(trustStore.getJkstruststore().getStorepassword().trim());
            }
            this.setType(StoreConstants.JKS_STORE_TYPE);

        }
    }

    /**
     * @param trustStore
     */
    private void setJCEKSFormat(final TrustStoreType trustStore) {
        if (trustStore.getJcekstruststore() != null) {
            if (trustStore.getJcekstruststore().getStorealias() != null) {
                this.setAlias(trustStore.getJcekstruststore().getStorealias().trim());
            }

            if (trustStore.getJcekstruststore().getStorelocation() != null) {
                this.setLocation(trustStore.getJcekstruststore().getStorelocation().trim());
            }

            if (trustStore.getJcekstruststore().getStorefolder() != null) {
                this.setFolder(trustStore.getJcekstruststore().getStorefolder().trim());
            }

            if (trustStore.getJcekstruststore().getStorepassword() != null) {
                this.setPassword(trustStore.getJcekstruststore().getStorepassword().trim());
            }
            this.setType(StoreConstants.JCEKS_STORE_TYPE);

        }
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model. CredentialManagerTrustStore #getType()
     */
    @Override
    public String getType() {
        return this.type;
    }

    /**
     * @param type
     *            the type to set
     */
    private void setType(final String type) {
        this.type = type;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model. CredentialManagerTrustStore #getAlias()
     */
    @Override
    public String getAlias() {
        return this.alias;
    }

    /**
     * @param alias
     *            the alias to set
     */
    private void setAlias(final String alias) {
        this.alias = alias;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model. CredentialManagerTrustStore #getLocation()
     */
    @Override
    public String getLocation() {
        return this.location;
    }

    /**
     * @param location
     *            the location to set
     */
    private void setLocation(final String location) {
        this.location = location;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model. CredentialManagerTrustStore #getFolder()
     */
    @Override
    public String getFolder() {
        return this.folder;
    }

    /**
     * @param folder
     *            the folder to set
     */
    private void setFolder(final String folder) {
        this.folder = folder;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model. CredentialManagerTrustStore #getPassword()
     */
    @Override
    public String getPassword() {
        return this.password;
    }

    /**
     * @param password
     *            the password to set
     */
    private void setPassword(final String password) {
        this.password = password;
    }

    /**
     * 
     * @return
     */
    private boolean isValidPassword() {
        if (this.password != null && !"".equals(this.password)) {
            return (this.password.length() > 5);
        }
        return true;
    }

    /**
     * @param source
     *            the source to set
     */
    private void setSource(final String source) {
        this.source = source;
    }

    /**
     * @return the source
     */
    @Override
    public String getSource() {
        return source;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service. CredentialManagerTrustStore#exists ()
     */
    @Override
    public boolean exists() {
        return new File(this.location).exists();
    }

}
