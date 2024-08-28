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
package com.ericsson.oss.itpf.security.pki.ra.tdps.common.mapper;

import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSResponse;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSResponseType;

/**
 * This class is a mapper class which is used to convert EDT to application level ENUM
 * 
 * @author tcsdemi
 *
 */
public class TDPSResponseMapper {

    /**
     * This method converts Model attribute EDT TDPSResponseType to application level ENUM TDPSResponse
     * 
     * @param tdpsResponseType
     *            is an EDT which can be SUCCESS,FAILURE
     * @return
     */
    public TDPSResponse fromModel(final TDPSResponseType tdpsResponseType) {
        TDPSResponse tdpsResponse = null;

        switch (tdpsResponseType) {
        case SUCCESS: {
            tdpsResponse = TDPSResponse.SUCCESS;
            break;
        }
        case FAILURE: {
            tdpsResponse = TDPSResponse.FAILURE;
            break;
        }
        default: {
            tdpsResponse = TDPSResponse.UNKNOWN_STATUS;
            break;
        }
        }

        return tdpsResponse;
    }

    /**
     * This method is used to convert Application level ENUM TDPSResponse to EDT TDPSResponseType
     * 
     * @param tdpsResponse
     *            is an ENUM which can have SUCCESS,FAILURE,UNKNOWN_STATUS
     * @return
     */
    public TDPSResponseType toModel(final TDPSResponse tdpsResponse) {
        TDPSResponseType tdpsResponsetype = null;

        switch (tdpsResponse) {
        case SUCCESS: {
            tdpsResponsetype = TDPSResponseType.SUCCESS;
            break;
        }
        case FAILURE: {
            tdpsResponsetype = TDPSResponseType.FAILURE;
            break;
        }
        default: {
            tdpsResponsetype = TDPSResponseType.UNKNOWN_STATUS;
            break;
        }
        }

        return tdpsResponsetype;
    }

}
