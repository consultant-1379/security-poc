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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.mappers;

import javax.inject.Inject;

import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSCertificateStatusType;

/**
 * This is a mapper class which converts CertificateStatus to TDPSCertificateStatusType which is a modeled event and vice versa
 * 
 * @author tcsdemi
 *
 */
public class TDPSCertificateStatusTypeMapper {

    @Inject
    Logger logger;

    /**
     * This method converts EntityType to TDPSEntityType
     * 
     * @param certificateStatus
     * @return
     */
    public TDPSCertificateStatusType toModel(final CertificateStatus certificateStatus) {
        TDPSCertificateStatusType tdpsCertificateStatusType = null;

        switch (certificateStatus) {
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

    /**
     * This method converts EntityType to TDPSEntityType
     * 
     * @param tdpsCertificateStatus
     * @return
     */
    public CertificateStatus fromModel(final TDPSCertificateStatusType tdpsCertificateStatus) {
        CertificateStatus certificateStatus = null;

        switch (tdpsCertificateStatus) {
        case ACTIVE: {
            certificateStatus = CertificateStatus.ACTIVE;
            break;
        }
        case INACTIVE: {
            certificateStatus = CertificateStatus.INACTIVE;
            break;

        }
        default: {
            logger.warn("Unknown certificateStatus received fromModel");
            break;
        }
        }
        return certificateStatus;
    }

}
