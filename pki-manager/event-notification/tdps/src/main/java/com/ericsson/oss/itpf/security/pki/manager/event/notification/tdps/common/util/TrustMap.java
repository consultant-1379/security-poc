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
package com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.util;

import java.security.cert.CertificateEncodingException;
import java.util.ArrayList;
import java.util.List;
import java.util.Map;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.CertificateStatus;
import com.ericsson.oss.itpf.security.pki.manager.event.notification.tdps.common.builders.TDPSCertificateInfoBuilder;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.cdt.TDPSCertificateInfo;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSCertificateStatusType;
import com.ericsson.oss.itpf.security.pki.ra.tdps.model.edt.TDPSEntityType;

/**
 * This is a Util class which builds a TrustMap to be added as an event attribute in TDPServiceResponse modeled event and TDPSCertificateEvent modeled event.
 * 
 * @author tcsdemi
 *
 */
public class TrustMap {
	private TrustMap(){
		
	}

    private static final Logger LOGGER = LoggerFactory.getLogger(TrustMap.class);

    /**
     * This method is used to get TrustMap which is built which consists of all entities who have publishToTDPS as True and List<Certificates> as its value.
     * 
     * @param entityType
     * @param allTrusts
     * @return
     */
    public static List<TDPSCertificateInfo> get(final TDPSEntityType entityType, final Map<String, List<Certificate>> allTrusts) {
        final List<TDPSCertificateInfo> tdpsCertificateInfoList = new ArrayList<TDPSCertificateInfo>();

        for (Map.Entry<String, List<Certificate>> entry : allTrusts.entrySet()) {
            final String eachEntityName = entry.getKey();
            final List<Certificate> certificates = allTrusts.get(eachEntityName);

            for (Certificate certificate : certificates) {
                final TDPSCertificateInfo tDPSCertificateInfo = generateTDOSCertificateInfo(entityType, eachEntityName, certificate);

                if (tDPSCertificateInfo != null) {
                    tdpsCertificateInfoList.add(tDPSCertificateInfo);
                }
            }
        }

        return tdpsCertificateInfoList;
    }

    private static TDPSCertificateInfo generateTDOSCertificateInfo(final TDPSEntityType entityType, final String entityName, final Certificate certificate) {
        TDPSCertificateInfo tDPSCertificateInfo = null;

        if (certificate == null) {
            return tDPSCertificateInfo;
        }

        try {
            final TDPSCertificateInfoBuilder tdPSCertificateInfoBuilder = new TDPSCertificateInfoBuilder().certificate(certificate.getX509Certificate().getEncoded()).entityName(entityName)
                    .entityType(entityType).serialNumber(certificate.getSerialNumber()).tDPSCertificateStatusType(toModel(certificate.getStatus())).issuerName(certificate.getIssuer().getName());

            tDPSCertificateInfo = tdPSCertificateInfoBuilder.build();
        } catch (final CertificateEncodingException certificateEncodingException) {
            LOGGER.debug("Certificate Encoding exception occured ", certificateEncodingException);
        }

        return tDPSCertificateInfo;
    }

    private static TDPSCertificateStatusType toModel(final CertificateStatus certificateStatus) {
        TDPSCertificateStatusType certificateStatusType = null;

        switch (certificateStatus) {
        case ACTIVE: {
            certificateStatusType = TDPSCertificateStatusType.ACTIVE;
            break;
        }
        case INACTIVE: {
            certificateStatusType = TDPSCertificateStatusType.INACTIVE;
            break;

        }
        default: {
            certificateStatusType = TDPSCertificateStatusType.UNKNOWN;
            break;
        }
        }

        return certificateStatusType;
    }
}