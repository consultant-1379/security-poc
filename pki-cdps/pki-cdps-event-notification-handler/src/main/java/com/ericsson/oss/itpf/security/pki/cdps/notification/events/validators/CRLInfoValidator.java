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
import com.ericsson.oss.itpf.security.pki.cdps.cdt.CRLInfo;

/**
 * This class validate the CRL Info data
 * 
 * @author xjagcho
 *
 */
public class CRLInfoValidator {

    @Inject
    private SystemRecorder systemRecorder;
    
    public static final String ERR_CRL_INFO_EMPTY = "CRL Info list object is empty";
    public static final String ERR_EMPTY_CA_CERTFICATE_INFO = "CaCertificateInfo object is empty";
    public static final String ERR_EMPTY_CANAME_SERIALNUMBER_CRL = "CAName or CACertSerialNumber or CRL is empty";

    /**
     * This method validate the list of CRLInfo data
     * 
     * @param crlInfos
     *            it contains CaCertificateInfo object it contains caName and certificate serial number and encoded CRL
     * 
     * @throws CRLValidationException
     *             Throws crlInfo list object is invalid
     */
    public void validate(final List<CRLInfo> crlInfos) throws CRLValidationException {
        if (ValidationUtils.isNullOrEmpty(crlInfos)) {
            systemRecorder.recordError("PKI_CDPS.CRL_INFO_EMPTY", ErrorSeverity.ERROR, "PKI CA", "CDPSService", "CRL Info list object found empty while validating CRL Publish request");
            throw new CRLValidationException(ERR_CRL_INFO_EMPTY);
        }
        for (CRLInfo crlInfo : crlInfos) {
            validate(crlInfo);
        }
    }

    /**
     * This method validate the CRLInfo data and checks CaCertificateInfo data is null or not
     * 
     * @param crlInfo
     *            it contains CaCertificateInfo it holds caName and certificate serial number
     * @throws CRLValidationException
     *             Exception throws when CaCertificateInfo or caName or SerialNumber is null
     */
    public void validate(final CRLInfo crlInfo) throws CRLValidationException {
        if (crlInfo.getCaCertificateInfo() == null) {
            systemRecorder.recordError("PKI_CDPS.EMPTY_CA_CERTFICATE_INFO", ErrorSeverity.ERROR, "PKI CA", "CDPSService", "CA Certificate Info found empty while validating CRL Publish request");
            throw new CRLValidationException(ERR_EMPTY_CA_CERTFICATE_INFO);
        }

        if (crlInfo.getCaCertificateInfo().getCaName() == null || crlInfo.getCaCertificateInfo().getCertificateSerialNumber() == null || crlInfo.getEncodedCRL() == null) {
            systemRecorder.recordError("PKI_CDPS.EMPTY_CANAME_SERIALNUMBER_CRL", ErrorSeverity.ERROR, "PKI CA", "CDPSService",
                    "CAName,CACertSerialNumber or CRL found empty while validating CRL Publish request");
            throw new CRLValidationException(ERR_EMPTY_CANAME_SERIALNUMBER_CRL);
        }
    }
}