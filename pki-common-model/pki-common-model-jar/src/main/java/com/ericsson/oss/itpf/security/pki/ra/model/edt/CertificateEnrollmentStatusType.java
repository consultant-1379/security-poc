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
 * This class defines model for certificate enrollment status event type which is an ENUM. This allows to identify which certificate enrollment status type either START, CERTIFICATE_SENT, SUCCESS or
 * FAILURE is being sent over the even bus.
 *
 * @author xgvgvgv
 *
 */
@EModel(description = "This Model defines enumerations for different types of enrollement status", namespace = ModelConstants.COMMON_MODEL_NAMESPACE, name = "CertificateEnrollmentStatusType", version = ModelConstants.COMMON_MODEL_VERSION)
@EdtDefinition
public enum CertificateEnrollmentStatusType {

    @EdtMember(value = 0, description = "Enum to indicate START status of Certificate Enrollment.")
    START,

    @EdtMember(value = 1, description = "Enum to indicate CERTIFICATE_SENT status of Certificate Enrollment.")
    CERTIFICATE_SENT,

    @EdtMember(value = 2, description = "Enum to indicate SUCCESS status of Certificate Enrollment.")
    SUCCESS,

    @EdtMember(value = 3, description = "Enum to indicate FAILURE status of Certificate Enrollment.")
    FAILURE

}
