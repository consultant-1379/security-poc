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
package com.ericsson.oss.itpf.security.pki.ra.cmp.model.edt;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.edt.EdtDefinition;
import com.ericsson.oss.itpf.modeling.annotation.edt.EdtMember;
import com.ericsson.oss.itpf.security.pki.ra.cmp.model.constants.CMPModelConstants;

/**
 * This class defines model for response type which is an ENUM. This allows
 * PKI-RA to identify which response either Key update response or
 * Initialization response is being sent over the event bus. Data structure for
 * both the response is same which is CertRepMessage, but the PKIBody
 * contentType is different for both Initialization and Key Update response. At
 * the PKI-Manager only CertRepMessage is formed and sent to PKI-RA for signing.
 * At PKI-RA to form a proper Key update response with PKIHeader and PKIBody RA
 * needs to know for which response is the CertRepMessage sent. Hence explicitly
 * an ENUM is needed to be declared in CMPServiceResponse.
 *
 * @author tcsdemi
 *
 */
@EModel(description = "This Model defines enum for type of response being sent. ", namespace =CMPModelConstants.CMP_NAMESPACE, name = "ResponseType", version = CMPModelConstants.VERSION)
@EdtDefinition
public enum ResponseType {

    @EdtMember(value = 3, description = "Unknown ERROR")
    UNKNOWN_ERROR_RESPONSE,

    @EdtMember(value = 2, description = "CMP Error Response")
    CMP_ERRORED_RESPONSE,

    @EdtMember(value = 1, description = "Key Update Response")
    KEY_UPDATE_RESPONSE,

    @EdtMember(value = 0, description = "Initialization Response")
    INITIALIZATION_RESPONSE

}
