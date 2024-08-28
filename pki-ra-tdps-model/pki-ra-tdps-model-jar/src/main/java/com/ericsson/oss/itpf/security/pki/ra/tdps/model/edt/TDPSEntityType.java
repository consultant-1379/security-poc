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
 * This class defines an ENUM for type of entity. TDPS can publish both Entity and CA Entity certificates. So for each certificate, whether it is of CA or entity will be defined by this enum.
 * 
 * @author tcslant
 *
 */
@EModel(description = "This Model defines enum for type of entity either CA or Entity. ", namespace = TDPSModelConstants.NAME_SPACE, name = "EntityType", version = TDPSModelConstants.VERSION)
@EdtDefinition
public enum TDPSEntityType {

    @EdtMember(value = 1, description = "End Entity type")
    ENTITY,

    @EdtMember(value = 2, description = "CA Entity type")
    CA_ENTITY,

    @EdtMember(value = 3, description = "Unknown Entity type")
    UNKNOWN_ENTITY

}
