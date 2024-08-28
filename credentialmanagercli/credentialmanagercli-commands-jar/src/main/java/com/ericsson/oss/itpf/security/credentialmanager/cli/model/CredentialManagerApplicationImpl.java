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
 * Represent the information that comes from the Application XML - Node
 * "application"
 * 
 */
public class CredentialManagerApplicationImpl implements
		CredentialManagerApplication {

	/**
     * 
     */
    private static final long serialVersionUID = 3543046333444247350L;
    private final List<CredentialManagerCertificate> certificates = new ArrayList<CredentialManagerCertificate>();
    private final List<CredentialManagerTrustStoreOnly> trustStores = new ArrayList<CredentialManagerTrustStoreOnly>();

    public CredentialManagerApplicationImpl(final Object applicationObj) {
        ApplicationType applicationType;

        if (applicationObj != null && applicationObj instanceof ApplicationType) {
            applicationType = (ApplicationType) applicationObj;
        } else {
            throw new CredentialManagerException("Loading information of XML Application Type...[Failed]");
        }

        final CertificatesType certificatesRequest = applicationType.getCertificates();
        final TrustStoresOnlyType trustStoresOnlyRequest = applicationType.getTruststores();

        // check if xml requires one or more certificates
        if (certificatesRequest != null && !certificatesRequest.getCertificate().isEmpty()) {
            for (final CertificateType certificate : certificatesRequest.getCertificate()) {
                this.certificates.add(new CredentialManagerCertificateImpl(certificate));
            }
        }

        // check if xml requires one or more trust
        if (trustStoresOnlyRequest != null && !trustStoresOnlyRequest.getTruststoreonly().isEmpty()) {
            for (final TrustStoreOnlyType trustStoreRequest : trustStoresOnlyRequest.getTruststoreonly()) {
                this.trustStores.add(new CredentialManagerTrustStoreOnlyImpl(trustStoreRequest));
            }
        }

    }

	/*
	 * (non-Javadoc)
	 * 
	 * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.model.
	 * CredentialManagerApplication #getCertificates()
	 */
	@Override
	public List<CredentialManagerCertificate> getCertificates() {
		return this.certificates;
	}

    /* (non-Javadoc)
     * @see com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerApplication#getTrustStoresOnly()
     */
    @Override
    public List<CredentialManagerTrustStoreOnly> getTrustStoresOnly() {
        return this.trustStores;
    }

}
