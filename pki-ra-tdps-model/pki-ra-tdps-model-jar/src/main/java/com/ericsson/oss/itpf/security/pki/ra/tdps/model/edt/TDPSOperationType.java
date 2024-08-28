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
 * This class defines an enum for publish status of the certificates. For eg: in case there is any Web cli command to publish certificate to RA, a CertificateEvent is sent to RA with publish status as
 * "PublishCertificate similarly for un-publishing any certificate"
 * 
 * @see com.ericsson.oss.itpf.security.pki.ra.tdps.model.events.TDPSCertificateEvent
 * @author tcslant
 *
 */
@EModel(description = "This TDPSOperationType Model defines enum for type of operation to be commited at TDPS whether to publish or unpublish. ", namespace = TDPSModelConstants.NAME_SPACE, name = "TDPSOperationType", version = TDPSModelConstants.VERSION)
@EdtDefinition
public enum TDPSOperationType {

    @EdtMember(value = 1, description = "Publish Certificate from TDPS")
    PUBLISH,

    @EdtMember(value = 2, description = "Unpublish Certificate from TDPS")
    UNPUBLISH,

    @EdtMember(value = 3, description = "Unknown Certificate from TDPS")
    UNKNOWN

}