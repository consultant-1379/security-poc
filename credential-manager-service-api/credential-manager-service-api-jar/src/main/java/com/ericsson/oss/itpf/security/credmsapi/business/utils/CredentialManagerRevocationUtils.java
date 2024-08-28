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


import com.ericsson.oss.itpf.security.credmsapi.api.model.CrlReason;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerRevocationReason;

public class CredentialManagerRevocationUtils {

    public static CredentialManagerRevocationReason convertRevocationReason(final CrlReason crlReason) {

        switch (crlReason) {

        case A_A_COMPROMISE:
            return CredentialManagerRevocationReason.AA_COMPROMISE;
        case AFFILIATION_CHANGED:
            return CredentialManagerRevocationReason.AFFILIATION_CHANGED;
        case CA_COMPROMISE:
            return CredentialManagerRevocationReason.CA_COMPROMISE;
        case CERTIFICATE_HOLD:
            return CredentialManagerRevocationReason.CERTIFICATE_HOLD;
        case CESSATION_OF_OPERATION:
            return CredentialManagerRevocationReason.CESSATION_OF_OPERATION;
        case KEY_COMPROMISE:
            return CredentialManagerRevocationReason.KEY_COMPROMISE;
        case PRIVILEGE_WITHDRAWN:
            return CredentialManagerRevocationReason.PRIVILEGE_WITHDRAWN;
        case REMOVE_FROM_CRL:
            return CredentialManagerRevocationReason.REMOVE_FROM_CRL;
        case SUPERSEDED:
            return CredentialManagerRevocationReason.SUPERSEDED;
        case UNSPECIFIED:
            return CredentialManagerRevocationReason.UNSPECIFIED;
        default: //unreachable
            return CredentialManagerRevocationReason.UNSPECIFIED;
        }
    }

}