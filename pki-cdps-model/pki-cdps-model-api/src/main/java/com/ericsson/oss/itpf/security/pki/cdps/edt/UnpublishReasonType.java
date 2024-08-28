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
 * UnpublishReasonType specifies an operation i.e REVOKED_CA_CERTIFICATE or EXPIRED_CA_CERTIFICATE. This can be passed as a input for UnPublish the CRL in CDPS
 * 
 * @author xjagcho
 *
 */
@EModel(description = "This Model defines enum for type of CDPS that is for revoked_ca_certificate or expired_ca_certificate", namespace = CDPSModelConstant.NAME_SPACE, name = "UnpublishReasonType", version = CDPSModelConstant.MODEL_VERSION)
@EdtDefinition
public enum UnpublishReasonType {

    @EdtMember(value = 0, description = "Revoked CRL is to be unpublished to CDPS")
    REVOKED_CA_CERTIFICATE,

    @EdtMember(value = 1, description = "Expired CRL is to be unpublished to CDPS")
    EXPIRED_CA_CERTIFICATE;
}