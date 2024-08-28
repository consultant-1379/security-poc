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


/**
 * CertificateFormat represents the needed informations related to the certificate type, at the moment it seems that just PKCS12 have to be supported
 */
public enum CertificateFormat {
	
	PKCS12,
	JKS,
	JCEKS,
	BASE_64,
	LEGACY_XML

}
