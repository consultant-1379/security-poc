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

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.credentialmanager.cli.exception.CredentialManagerException;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.*;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.*;

/**
 * 
 * Hold the information needed to create Certificate, KeyStore and TrustSore
 * 
 */
public class CredentialManagerTrustStoreOnlyImpl implements CredentialManagerTrustStoreOnly {
    /**
     * 
     */
    private static final long serialVersionUID = -8816549687211413421L;
    /**
     * 
     */
    private String trustProfileName;
    private final List<CredentialManagerTrustStore> trustStores = new ArrayList<CredentialManagerTrustStore>();
    private final List<CredentialManagerTrustStore> crlStores = new ArrayList<CredentialManagerTrustStore>();
    private final CredentialManagerPostScriptCaller postScript = new CredentialManagerPostScriptCallerImpl();
    private final List<CredentialManagerCheckAction> checkActions = new ArrayList<CredentialManagerCheckAction>();


    public CredentialManagerTrustStoreOnlyImpl(final Object trustStoreOnlyObj) {
        
        TrustStoreOnlyType trustStoreOnly;

        if (trustStoreOnlyObj != null && trustStoreOnlyObj instanceof TrustStoreOnlyType) {
            trustStoreOnly = (TrustStoreOnlyType) trustStoreOnlyObj;
        } else {
            throw new CredentialManagerException("Loading information of XML TrustStoreOnly Type...[Failed]");
        }

        this.setTrustProfileName(trustStoreOnly.getTrustprofilename());

        for (final TrustStoreType trustStore : trustStoreOnly.getTruststore()) {
            this.trustStores.add(new CredentialManagerTrustStoreImpl(trustStore));
        }

        for (final CrlStoreType crlStore : trustStoreOnly.getCrlstore()) {
            this.crlStores.add(new CredentialManagerTrustStoreImpl(crlStore));
        }

        if (trustStoreOnly.getPostscript() != null) {
            ((CredentialManagerPostScriptCallerImpl) this.postScript).importPostScriptCmd(trustStoreOnly.getPostscript());
        }

        if (trustStoreOnly.getOncheckresult() != null) {
            for (final CheckActionType checkAction : trustStoreOnly.getOncheckresult().getActionlist()) {
                this.checkActions.add(new CredentialManagerCheckActionImpl(checkAction));
            }
        }

    }

    
    @Override
    public String getTrustProfileName() {
        return this.trustProfileName;
    }

    /**
     * @param trustProfileName
     */
    private void setTrustProfileName(final String trustProfileName) {
        this.trustProfileName = trustProfileName;
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

    /**
     * @return the crlStores
     */
    @Override
    public List<CredentialManagerTrustStore> getCrlStores() {
        return this.crlStores;
    }
    
    /**
     * @return the postScript
     */
    @Override
    public CredentialManagerPostScriptCaller getPostScript() {
        return this.postScript;
    }


    /**
     * @return the crlStores
     */
    @Override
    public List<CredentialManagerCheckAction> getCheckAction() {
        return this.checkActions;
    }



}
