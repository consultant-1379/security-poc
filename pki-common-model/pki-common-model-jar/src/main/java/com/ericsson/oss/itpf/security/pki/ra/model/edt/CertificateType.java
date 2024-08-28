/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.model.edt;

import com.ericsson.oss.itpf.modeling.annotation.EModel;
import com.ericsson.oss.itpf.modeling.annotation.edt.EdtDefinition;
import com.ericsson.oss.itpf.modeling.annotation.edt.EdtMember;
import com.ericsson.oss.itpf.security.pki.ra.model.common.constants.ModelConstants;

/**
 * Class to define enumerations for different certificate types. This allows to identify which certificate type - OAM , IPSEC or UNKNOWN is being sent over the event bus.
 * 
 * @author xgvgvgv
 *
 */
@EModel(description = "This Model defines enumerations for different certificate types", namespace = ModelConstants.COMMON_MODEL_NAMESPACE, name = "CertificateType", version = ModelConstants.COMMON_MODEL_VERSION)
@EdtDefinition
public enum CertificateType {

    @EdtMember(value = 1, description = "Enum for IPSEC certificate type.")
    IPSEC,

    @EdtMember(value = 2, description = "Enum for OAM certificate type.")
    OAM,

    @EdtMember(value = 3, description = "Enum for UNKNOWN certificate type.")
    UNKNOWN
}
