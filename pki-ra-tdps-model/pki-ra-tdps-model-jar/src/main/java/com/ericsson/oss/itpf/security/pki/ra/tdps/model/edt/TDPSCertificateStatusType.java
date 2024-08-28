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
 * This is a modeled EDT which holde certificate status whether certificate is ACTIVE or INACTIVE
 * 
 * @author tcsdemi
 *
 */
@EModel(description = "This Model defines enum for type of certificateStatus whether active or inactive. ", namespace = TDPSModelConstants.NAME_SPACE, name = "TDPSCertificateStatusType", version = TDPSModelConstants.VERSION)
@EdtDefinition
public enum TDPSCertificateStatusType {

    @EdtMember(value = 1, description = "Active certificate to be published or is published in TDPS")
    ACTIVE,

    @EdtMember(value = 2, description = "Inactive certificate to be published or is published in TDPS")
    INACTIVE,

    @EdtMember(value = 3, description = "Unknown Certificate Status")
    UNKNOWN

}
