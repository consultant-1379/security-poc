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
package com.ericsson.oss.itpf.security.pki.cdps.edt;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.edt.EdtDefinition;
import com.ericsson.oss.itpf.modeling.annotation.edt.EdtMember;
import com.ericsson.oss.itpf.security.pki.cdps.constants.CDPSModelConstant;

/**
 * CDPSResponseType specifies the status SUCCESS or FAILURE CRLAcknowldgement message holds this parameter to process.
 * 
 * @author xnarsir
 *
 */

@EModel(description = "This Model defines enum for type of CDPSResponseType status that is Published or Unpublished ", namespace = CDPSModelConstant.NAME_SPACE, name = "CDPSResponseType", version = CDPSModelConstant.MODEL_VERSION)
@EdtDefinition
public enum CDPSResponseType {
    @EdtMember(value = 0, description = "CRL Published/unpublished successfully for SUCCESS")
    SUCCESS,

    @EdtMember(value = 1, description = "CRL Published/Unpublished unsuccessfully for Failure")
    FAILURE;
}
