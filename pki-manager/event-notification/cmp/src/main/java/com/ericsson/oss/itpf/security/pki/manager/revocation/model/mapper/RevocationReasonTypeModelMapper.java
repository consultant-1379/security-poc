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
package com.ericsson.oss.itpf.security.pki.manager.revocation.model.mapper;

import com.ericsson.oss.itpf.security.pki.common.cmp.revocation.model.data.RevocationRequest;
import com.ericsson.oss.itpf.security.pki.common.model.crl.revocation.RevocationReason;

/**
 * This class is a mapper to RevocationReasonType.
 * 
 * @author tcsramc
 *
 */
public class RevocationReasonTypeModelMapper {
    /**
     * This method is used to get parameters from the revocationServiceRequest.
     * 
     * @param revocationRequest
     *            from which attributes has to be fetched.
     * @return RevocationReason
     */

    public RevocationReason fromModel(final RevocationRequest revocationRequest) {

        RevocationReason revocationReason = null;
        switch (revocationRequest.getRevocationReason().toUpperCase()) {
        case "SUPERSEDED": {
            revocationReason = RevocationReason.SUPERSEDED;
            break;
        }
        default: {
            revocationReason = RevocationReason.UNSPECIFIED;
            break;
        }
        }
        return revocationReason;

    }

}
