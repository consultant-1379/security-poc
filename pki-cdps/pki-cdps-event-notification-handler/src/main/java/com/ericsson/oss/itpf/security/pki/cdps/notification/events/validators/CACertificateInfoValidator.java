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
package com.ericsson.oss.itpf.security.pki.cdps.notification.events.validators;

import java.util.List;

import javax.inject.Inject;

import com.ericsson.oss.itpf.sdk.recording.ErrorSeverity;
import com.ericsson.oss.itpf.sdk.recording.SystemRecorder;
import com.ericsson.oss.itpf.security.pki.cdps.api.exception.CRLValidationException;
import com.ericsson.oss.itpf.security.pki.common.util.ValidationUtils;
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CACertificateInfo;

/**
 * This class validate the CACertificate Info object data
 * 
 * @author xjagcho
 * 
 */
public class CACertificateInfoValidator {

    @Inject
    private SystemRecorder systemRecorder;

    public static final String ERR_EMPTY_CA_CERTFICATE_INFO_LIST = "CaCertificateInfo list object is empty";
    public static final String ERR_EMPTY_CANAME_SERIALNUMBER = "CAName or CACertSerialNumber is empty";

    /**
     * This method validate the list of CACertificateInfo object
     * 
     * @param caCertificateInfos
     *            it contains list of CACertificateInfo it holds CAName or Certificate SerialNumber
     * @throws CRLValidationException
     *             throws when list of caCertificateInfo are invalid
     */
    public void validate(final List<CACertificateInfo> caCertificateInfos) throws CRLValidationException {
        if (ValidationUtils.isNullOrEmpty(caCertificateInfos)) {
            systemRecorder.recordError("PKI_CDPS.EMPTY_CA_CERTFICATE_INFO_LIST", ErrorSeverity.ERROR, "CDPSService", "CDPSService",
                    "CaCertificateInfo list object found empty while validating CRL Unpublish request");
            throw new CRLValidationException(ERR_EMPTY_CA_CERTFICATE_INFO_LIST);
        }

        for (CACertificateInfo caCertificateInfo : caCertificateInfos) {
            validate(caCertificateInfo);
        }
    }

    /**
     * This method validate the CAName or Certificate SerialNumber
     * 
     * @param caCertificateInfo
     *            it contains CAName or Certificate SerialNumber
     * @throws CRLValidationException
     *             throws when CAName or Certificate SerialNumber is null
     */
    public void validate(final CACertificateInfo caCertificateInfo) throws CRLValidationException {
        if (caCertificateInfo.getCaName() == null || caCertificateInfo.getCertificateSerialNumber() == null) {
            systemRecorder.recordError("PKI_CDPS.EMPTY_CANAME_SERIALNUMBER", ErrorSeverity.ERROR, "CDPSService", "CDPSService",
                    "CAName or CACertSerialNumber found empty while validating CRL Unpublish request");
            throw new CRLValidationException(ERR_EMPTY_CANAME_SERIALNUMBER);
        }
    }
}