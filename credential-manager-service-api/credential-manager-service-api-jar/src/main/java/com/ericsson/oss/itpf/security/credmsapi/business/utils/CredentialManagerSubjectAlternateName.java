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
package com.ericsson.oss.itpf.security.credmsapi.business.utils;

import java.io.Serializable;
import java.util.List;

import org.bouncycastle.asn1.x509.Attribute;

public interface CredentialManagerSubjectAlternateName extends Serializable {
	enum ALTERNATE_NAME_TYPE {
		DIRECTORY_NAME, DNS, EMAIL, URI, IP_ADDRESS, OTHER_NAME, REGISTERED_ID;
	}

	/**
	 * @return the type
	 */
	ALTERNATE_NAME_TYPE getType();

	/**
	 * @param type
	 *            the type to set
	 */
	void setType(ALTERNATE_NAME_TYPE type);

	/**
	 * @return the value
	 */
	List<String> getValue();

	/**
	 * @param value
	 *            the value to set
	 */
	void setValue(List<String> value);

	Attribute getAttribute();

	String getSubjectAlternativeName();

}