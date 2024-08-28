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

public enum CredentialManagerActionCauseEnum {

    CERTIFICATE_UPDATE("certificateUpdate"),
    TRUST_UPDATE("trustUpdate"),
    CRL_UPDATE("crlUpdate");
    

    private final String name;       

    private CredentialManagerActionCauseEnum(final String s) {
        this.name = s;
    }

    public boolean equals(final String otherName) {
        return (otherName == null) ? false : this.name.equals(otherName);
    }

    @Override
    public String toString() {
       return this.name;
    }
    
}
