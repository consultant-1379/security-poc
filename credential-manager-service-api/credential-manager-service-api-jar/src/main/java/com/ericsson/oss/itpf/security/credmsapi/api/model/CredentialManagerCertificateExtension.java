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

import java.io.Serializable;
import java.util.Map;

import org.bouncycastle.asn1.x509.Attribute;

public interface CredentialManagerCertificateExtension extends Serializable {

	/**
	 * @return the attributes
	 */
	Map<String, Attribute> getAttributes();

	String getSubjectAlternativeName();

	/**
	 * @param attributes
	 */
	void setAttributes(Map<String, Attribute> attributes);

	/**
	 * @param subjectAlternativeName
	 */
	void setSubjectAlternativeName(String subjectAlternativeName);

}