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
package com.ericsson.oss.itpf.security.credentialmanager.cli.service.api;

import java.io.Serializable;
import java.util.List;

public interface CredentialManagerApplication extends Serializable {

	/**
	 * @return the certificates
	 */
	List<CredentialManagerCertificate> getCertificates();
	
	
	/**
	 * 
	 * @return
	 */
	List<CredentialManagerTrustStoreOnly> getTrustStoresOnly();
	

	// TODO manage of CRL 
	// CrlUpdateModeType getCrlupdatemode();

	// TODO manage KeyRequest
	// KeyRequestsType getKeyrequests();

}