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
package com.ericsson.oss.itpf.security.credmservice.api.model;

public enum CredentialManagerEntityType {
	ENTITY("entity"), CA_ENTITY("caentity"), ALL("all");

	String value;

	CredentialManagerEntityType(final String value) {
		this.value = value;
	}

	/*
	 * (non-Javadoc)
	 * 
	 * @see java.lang.Enum#toString()
	 */
	@Override
	public String toString() {
		// TODO Auto-generated method stub
		return value;
	}

	public static CredentialManagerEntityType fromString(final String value) {
		if (value != null) {
			for (final CredentialManagerEntityType entityType : CredentialManagerEntityType.values()) {
				if (value.equalsIgnoreCase(entityType.value)) {
					return entityType;
				}
			}
		}
		return null;
	}
}
