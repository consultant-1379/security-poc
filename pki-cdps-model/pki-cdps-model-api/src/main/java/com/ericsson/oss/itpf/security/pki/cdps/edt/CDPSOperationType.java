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
 * CDPSOperationType specifies an operation i.e PUBLISH or UNPUBLISH This can be passed as a input for Publish/Unpublish the CRL in CDPS
 * 
 * @author xnarsir
 *
 */

@EModel(description = "This Model defines enum for type of CDPS that is for Publish or Unpublish ", namespace = CDPSModelConstant.NAME_SPACE, name = "CDPSOperationType", version = CDPSModelConstant.MODEL_VERSION)
@EdtDefinition
public enum CDPSOperationType {

    @EdtMember(value = 0, description = "CRL is to be published to Cdps")
    PUBLISH,

    @EdtMember(value = 1, description = "CRL is to be Unpublished from Cdps")
    UNPUBLISH;
}
