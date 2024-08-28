/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2015
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.cmp.revocation.model.edt;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.edt.EdtDefinition;
import com.ericsson.oss.itpf.modeling.annotation.edt.EdtMember;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.constants.CMPModelConstants;

/**
 * This class defines model for Revocation reason type which is an ENUM. This allows PKI-Manager to identify the reason for the certificate to revoke.
 * 
 * @author tcsramc
 *
 */
@EModel(description = "This Model defines enum for RevocationReasonType ", namespace = CMPModelConstants.CMP_NAMESPACE, name = "RevocationReasonType", version = CMPModelConstants.VERSION)
@EdtDefinition
public enum RevocationReasonType {

    @EdtMember(value = 10, description = " AA COMPROMISE")
    AA_COMPROMISE,

    @EdtMember(value = 9, description = "PRIVILEGE WITHDRAWN")
    PRIVILEGE_WITHDRAWN,

    @EdtMember(value = 8, description = "REMOVE FROM CRL")
    REMOVE_FROM_CRL,

    @EdtMember(value = 6, description = "CERTIFICATE HOLD")
    CERTIFICATE_HOLD,

    @EdtMember(value = 5, description = "CESSATION OF OPERATION")
    CESSATION_OF_OPERATION,

    @EdtMember(value = 4, description = "SUPERSEDED")
    SUPERSEDED,

    @EdtMember(value = 3, description = "AFFILIATION CHANGED")
    AFFILIATION_CHANGED,

    @EdtMember(value = 2, description = "CA COMPROMISE")
    CA_COMPROMISE,

    @EdtMember(value = 1, description = "KEY COMPROMISE")
    KEY_COMPROMISE,

    @EdtMember(value = 0, description = "UNSPECIFIED")
    UNSPECIFIED

}
