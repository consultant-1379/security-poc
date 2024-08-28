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

import java.math.BigInteger;
import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.credentialmanager.cli.exception.CredentialManagerException;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.CertificateType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.CheckActionType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.CrlStoreType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.KeyStoreType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.TrustStoreType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerCertificate;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerCheckAction;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerConnectorManagedType;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerKeyStore;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerPostScriptCaller;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerTBSCertificate;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerTrustStore;

/**
 * 
 * Hold the information needed to create Certificate, KeyStore and TrustSore
 * 
 */
public class CredentialManagerCertificateImpl implements CredentialManagerCertificate {
    /**
     * 
     */
    private static final long serialVersionUID = 8277097872390549944L;
    private CredentialManagerTBSCertificate tbsCertificate;
    private String endEntityProfileName;
    private String signatureAlgorithm;
    private BigInteger keypairSize;
    private String keypairAlgorithm;
    //	private Integer connectorPort;
    private CredentialManagerConnectorManagedType connectorManagedType;
    private final List<CredentialManagerKeyStore> keyStores = new ArrayList<CredentialManagerKeyStore>();
    private final List<CredentialManagerTrustStore> trustStores = new ArrayList<CredentialManagerTrustStore>();
    private final List<CredentialManagerTrustStore> crlStores = new ArrayList<CredentialManagerTrustStore>();
    private final CredentialManagerPostScriptCaller postScript = new CredentialManagerPostScriptCallerImpl();
    private final List<CredentialManagerCheckAction> checkActions = new ArrayList<CredentialManagerCheckAction>();

    private boolean certificateChain;

    public CredentialManagerCertificateImpl(final Object certificateTypeObj) {
        CertificateType certificateType;

        if (certificateTypeObj != null && certificateTypeObj instanceof CertificateType) {
            certificateType = (CertificateType) certificateTypeObj;
        } else {
            throw new CredentialManagerException("Loading information of XML Certificate Type...[Failed]");
        }
        this.setTbsCertificate(new CredentialManagerTBSCertificateImpl(certificateType.getTbscertificate()));

        if (certificateType.getKeypair() != null) {
            this.setKeypairAlgorithm(certificateType.getKeypair().getKeypairalgorithm().trim());
            this.setKeypairSize(certificateType.getKeypair().getKeypairsize());
        }
        // data moved form XML to Profile
        // setSignatureAlgorithm(certificateType.getSignaturealgorithm().trim());
        this.setSignatureAlgorithm("SHA256WithRSAEncryption");

        this.setEndEntityProfileName(certificateType.getEndentityprofilename());

        for (final KeyStoreType keyStore : certificateType.getKeystore()) {
            this.keyStores.add(new CredentialManagerKeyStoreImpl(keyStore));
        }

        for (final TrustStoreType trustStore : certificateType.getTruststore()) {
            this.trustStores.add(new CredentialManagerTrustStoreImpl(trustStore));
        }

        for (final CrlStoreType crlStore : certificateType.getCrlstore()) {
            this.crlStores.add(new CredentialManagerTrustStoreImpl(crlStore));
        }
        // setConnectorManaged(certificateType.getConnectormanaged());

        if (certificateType.getPostscript() != null) {
            ((CredentialManagerPostScriptCallerImpl) this.postScript).importPostScriptCmd(certificateType.getPostscript());
        }

        if (certificateType.getOncheckresult() != null) {
            for (final CheckActionType checkAction : certificateType.getOncheckresult().getActionlist()) {
                this.checkActions.add(new CredentialManagerCheckActionImpl(checkAction));
            }
        }

        if (certificateType.isCertificatechain() != null) {
            this.setCertificateChain(certificateType.isCertificatechain().booleanValue());
        } else {
            this.setCertificateChain(false);
        }

    }

    /**
     * @return the postScript
     */
    @Override
    public CredentialManagerPostScriptCaller getPostScript() {
        return this.postScript;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model. CredentialManagerCertificate #getTbsCertificate()
     */
    @Override
    public CredentialManagerTBSCertificate getTbsCertificate() {
        return this.tbsCertificate;
    }

    /**
     * @param tbsCertificate
     *            the tbsCertificate to set
     */
    private void setTbsCertificate(final CredentialManagerTBSCertificate tbsCertificate) {
        this.tbsCertificate = tbsCertificate;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model. CredentialManagerCertificate #getSignatureAlgorithm()
     */
    @Override
    public String getSignatureAlgorithm() {
        return this.signatureAlgorithm;
    }

    /**
     * @param signatureAlgorithm
     *            the signatureAlgorithm to set
     */
    private void setSignatureAlgorithm(final String signatureAlgorithm) {
        this.signatureAlgorithm = signatureAlgorithm;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model. CredentialManagerCertificate #getKeypairSize()
     */
    @Override
    public BigInteger getKeypairSize() {
        return this.keypairSize;
    }

    /**
     * @param keypairSize
     *            the keypairSize to set
     */
    private void setKeypairSize(final BigInteger keypairSize) {
        this.keypairSize = keypairSize;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model. CredentialManagerCertificate #getKeypairAlgorithm()
     */
    @Override
    public String getKeypairAlgorithm() {
        return this.keypairAlgorithm;
    }

    /**
     * @param keypairAlgorithm
     *            the keypairAlgorithm to set
     */
    private void setKeypairAlgorithm(final String keypairAlgorithm) {
        this.keypairAlgorithm = keypairAlgorithm;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model. CredentialManagerCertificate #getKeyStores()
     */
    @Override
    public List<CredentialManagerKeyStore> getKeyStores() {
        return this.keyStores;
    }

    /**
     * @return the crlStores
     */
    @Override
    public List<CredentialManagerTrustStore> getCrlStores() {
        return this.crlStores;
    }

    /**
     * @return the crlStores
     */
    @Override
    public List<CredentialManagerCheckAction> getCheckAction() {
        return this.checkActions;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model. CredentialManagerCertificate #getTrustStores()
     */
    @Override
    public List<CredentialManagerTrustStore> getTrustStores() {
        return this.trustStores;
    }

    @Override
    public String getEndEntityProfileName() {
        return this.endEntityProfileName;
    }

    /**
     * @param endEntityProfileName
     *            the endEntityProfileName to set
     */
    private void setEndEntityProfileName(final String endEntityProfileName) {
        this.endEntityProfileName = endEntityProfileName;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.api. CredentialManagerCertificate#getConnectormanaged()
     */
    @Override
    public CredentialManagerConnectorManagedType getConnectorManaged() {
        return this.connectorManagedType;
    }

    @Override
    public boolean getCertificateChain() {
        return this.certificateChain;
    }

    private void setCertificateChain(final boolean certificateChain) {
        this.certificateChain = certificateChain;
    }

    /**
     * @param connectorManagedType
     *            the connectorManagedType to set
     */
    // // private void setConnectorManaged(final ConnectorManagedType
    // connectorManagedType) {
    // if (connectorManagedType != null) {
    // this.connectorManagedType =
    // CredentialManagerConnectorManagedType.fromValue(connectorManagedType.value());
    // } else {
    // this.connectorManagedType =
    // CredentialManagerConnectorManagedType.UNDEFINED;
    // }
    // }

}
