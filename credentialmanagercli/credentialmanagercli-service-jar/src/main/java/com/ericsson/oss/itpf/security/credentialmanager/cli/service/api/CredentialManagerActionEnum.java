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


public enum CredentialManagerActionEnum {

    VM_RESTART("VMRestart"),
    HTTPS_CONNECTOR_RESTART("HTTPSConnectorRestart"),
    RUN_SCRIPT("RunScript");
    
    private final String name;       

    private CredentialManagerActionEnum(final String s) {
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
