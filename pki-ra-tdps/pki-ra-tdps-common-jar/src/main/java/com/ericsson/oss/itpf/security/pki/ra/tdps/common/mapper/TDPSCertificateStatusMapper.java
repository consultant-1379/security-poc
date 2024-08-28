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

import com.ericsson.oss.itpf.security.pki.ra.tdps.common.enums.TDPSCertificateStatus;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSCertificateStatusType;

/**
 * This class is used as a mapper for Certficate status EModel attribute TDPSCertificateStatusType towards application level ENUM TDPSCertificateStatus
 * 
 * @author tcsdemi
 *
 */
public class TDPSCertificateStatusMapper {

    /**
     * This method is used to convert TDPSCertificateStatusType (EDT) to TDPSCertificateStatus(ENUM)
     * 
     * @param tdpsCertificateStatusType
     *            is an EDT which describes certificate status
     * 
     * @return
     */
    public TDPSCertificateStatus fromModel(final TDPSCertificateStatusType tdpsCertificateStatusType) {
        TDPSCertificateStatus tdpsCertificateStatus = null;

        switch (tdpsCertificateStatusType) {
        case ACTIVE: {
            tdpsCertificateStatus = TDPSCertificateStatus.ACTIVE;
            break;
        }
        case INACTIVE: {
            tdpsCertificateStatus = TDPSCertificateStatus.INACTIVE;
            break;
        }
        default: {
            tdpsCertificateStatus = TDPSCertificateStatus.UNKNOWN;
            break;
        }

        }

        return tdpsCertificateStatus;
    }

    /**
     * This method converts TDPSCertificateStatus(ENUM) to TDPSCertificateStatusType(EDT)
     * 
     * @param tdpsCertificateStatus
     *            is an application level ENUM which can have ACTIVE/INACTIVE or UNKNOWN status
     * 
     * @return
     */
    public TDPSCertificateStatusType toModel(final TDPSCertificateStatus tdpsCertificateStatus) {
        TDPSCertificateStatusType tdpsCertificateStatusType = null;

        switch (tdpsCertificateStatus) {
        case ACTIVE: {
            tdpsCertificateStatusType = TDPSCertificateStatusType.ACTIVE;
            break;
        }
        case INACTIVE: {
            tdpsCertificateStatusType = TDPSCertificateStatusType.INACTIVE;
            break;
        }
        default: {
            tdpsCertificateStatusType = TDPSCertificateStatusType.UNKNOWN;
            break;
        }

        }

        return tdpsCertificateStatusType;
    }

}
