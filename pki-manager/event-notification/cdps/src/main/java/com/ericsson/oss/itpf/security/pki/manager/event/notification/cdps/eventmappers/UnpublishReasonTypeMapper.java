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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.cdps.eventmappers;

import com.ericsson.oss.itpf.security.pki.cdps.edt.UnpublishReasonType;
import com.ericsson.oss.itpf.security.pki.manager.common.enums.CRLUnpublishType;

/**
 * This Class prepares the UnPublish Reason Type to map using CRLUnpublishType
 * 
 * @author xjagcho
 *
 */
public class UnpublishReasonTypeMapper {
    /**
     * This method process the CRLUnpublishType object
     * 
     * @param crlUnpublishType
     *            it holds revoked_ca_certificate,expired_ca_certificate and user_invoked_request
     * 
     * @return UnpublishReasonType
     */
    public UnpublishReasonType fromModel(final CRLUnpublishType crlUnpublishType) {
        UnpublishReasonType unpublishReasonType = null;

        switch (crlUnpublishType) {
        case REVOKED_CA_CERTIFICATE:
            unpublishReasonType = UnpublishReasonType.REVOKED_CA_CERTIFICATE;
            break;
        case EXPIRED_CA_CERTIFICATE:
            unpublishReasonType = UnpublishReasonType.EXPIRED_CA_CERTIFICATE;
            break;
        default:
            break;
        }

        return unpublishReasonType;
    }
}