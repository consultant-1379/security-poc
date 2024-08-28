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
package com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.edt.EdtDefinition;
import com.ericsson.oss.itpf.modeling.annotation.edt.EdtMember;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.constants.TDPSModelConstants;

/**
 * This class defines model for response type which is an ENUM. This allows PKI-RA to identify whether sent response is a success response or failed response. Based on this from response event, RA can
 * act based on the error info. In case of any exception at PKI-Manager side while service TDPS request, response type is set to Failure.
 * 
 * @see com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPServiceResponse
 * @author tcsdemi
 *
 */
@EModel(description = "This TDPSResponseType Model defines enum for type of response being sent whether request sent to TDPS was a success or a failure. ", namespace = TDPSModelConstants.NAME_SPACE, name = "TDPSResponseType", version = TDPSModelConstants.VERSION)
@EdtDefinition
public enum TDPSResponseType {

    @EdtMember(value = 1, description = "Success")
    SUCCESS,

    @EdtMember(value = 2, description = "Failure")
    FAILURE,

    @EdtMember(value = 3, description = "Unknown status")
    UNKNOWN_STATUS

}
