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
package com.ericsson.oss.itpf.security.credmsapi.storage.api;

public interface StorageConstants {

	/**
	 * JKS Store type
	 */
	String JKS_STORE_TYPE = "JKS";

	/**
	 * JCEKS Store type
	 * 
	 */

	String JCEKS_STORE_TYPE = "JCEKS";

	/**
	 * PKCS#12 or P12 store type
	 * 
	 */

	String PKCS12_STORE_TYPE = "PKCS12";

	/**
	 * Encoded in Base 64 format
	 */
	String BASE64_PEM_STORE_TYPE = "BASE_64_PEM";
	//String BASE64_DER_STORE_TYPE = "BASE_64_DER";
	
	/**
         * Encoded in Base 64 format
         */
        String LEGACY_XML_STORE_TYPE = "LEGACY_XML";

}
