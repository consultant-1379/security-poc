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
import java.math.BigInteger;
import java.util.List;

public interface CredentialManagerCertificate extends Serializable {

	/**
	 * @return the tbsCertificate
	 */
	CredentialManagerTBSCertificate getTbsCertificate();

	/**
	 * @return the signatureAlgorithm
	 */
	String getSignatureAlgorithm();

	/**
	 * 
	 * @return End Entity Profile Name
	 */
	String getEndEntityProfileName();

	/**
	 * @return the keypairSize
	 */
	BigInteger getKeypairSize();

	/**
	 * @return the keypairAlgorithm
	 */
	String getKeypairAlgorithm();

	/**
	 * @return the keyStores
	 */
	List<CredentialManagerKeyStore> getKeyStores();

	/**
	 * @return the trustStores
	 */
	List<CredentialManagerTrustStore> getTrustStores();

	/**
	 * @return the trustStores
	 */
	List<CredentialManagerCheckAction> getCheckAction();

	CredentialManagerPostScriptCaller getPostScript();

	/**
	 * 
	 * @return
	 */
	List<CredentialManagerTrustStore> getCrlStores();

	CredentialManagerConnectorManagedType getConnectorManaged();

	boolean getCertificateChain();

}