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
package com.ericsson.oss.itpf.security.credentialmanager.cli.service.api;

import java.io.Serializable;

public interface CredentialManagerKeyStore extends Serializable {

	/**
	 * @return the privateKeyLocation
	 */
	String getPrivateKeyLocation();

	/**
	 * @return
	 */
	String getCertificateLocation();
	
	/**
	 * @return the keyStorelocation
	 */
	String getKeyStorelocation();

	/**
	 * @return the keyStorefolder
	 */
//	String getKeyStorefolder();

	/**
	 * @return the alias
	 */
	String getAlias();

	/**
	 * @return the password
	 */
	String getPassword();

	/**
	 * @return the type
	 */
	String getType();

	/**
	 * 
	 * @return true if KeyStore already exists or false otherwise
	 */
	boolean exists();

	/**
	 * @return
	 */
	void delete();



}