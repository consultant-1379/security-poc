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
package com.ericsson.oss.itpf.security.pki.common.cmp.model;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DERUTF8String;
import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.x509.ReasonFlags;

import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;

/**
 * This class forms PKIFailureInfo
 * 
 * @author tcsramc
 * 
 */
public class PKIStatusInfoMapper {
    private PKIStatusInfoMapper() {

    }

    /**
     * This method forms PKIFreeText and PKIFailureInfo from the errorMessage.
     * 
     * @param errorMessage
     *            error message from which failure info need to be extracted
     * @return error status information
     */
    public static PKIStatusInfo map(final String errorMessage) {

        PKIStatusInfo errorStatusInfo;
        final PKIStatus pKIStatus = PKIStatus.getInstance(new ASN1Integer(2));
        PKIFreeText pKIFreeText;
        PKIFailureInfo pKIFailureInfo;

        switch (errorMessage) {

        case ErrorMessages.IO_EXCEPTION:
        case ErrorMessages.DIGITAL_SIGNATURE_ERROR:
        case ErrorMessages.IAK_AUTHENTICATION_FAILED:
        case ErrorMessages.BAD_MESSAGE_CHECK: {
            pKIFreeText = new PKIFreeText(new DERUTF8String(ErrorMessages.BAD_MESSAGE_CHECK));
            pKIFailureInfo = new PKIFailureInfo(new ReasonFlags(1 << 1));
            break;
        }

        case ErrorMessages.TRANSACTION_ID_IN_USE: {
            pKIFreeText = new PKIFreeText(new DERUTF8String(ErrorMessages.TRANSACTION_ID_IN_USE));
            pKIFailureInfo = new PKIFailureInfo(new ReasonFlags(1 << 21));
            break;
        }
        case ErrorMessages.NOT_SUPPORTED_REQUEST_TYPE: {
            pKIFreeText = new PKIFreeText(new DERUTF8String(ErrorMessages.NOT_SUPPORTED_REQUEST_TYPE));
            pKIFailureInfo = new PKIFailureInfo(new ReasonFlags(1 << 2));
            break;
        }
        case ErrorMessages.HEADER_VERSION_ERROR:
        case ErrorMessages.HEADER_SENDER_FORMAT_ERROR: {
            pKIFreeText = new PKIFreeText(new DERUTF8String(ErrorMessages.HEADER_VERSION_ERROR));
            pKIFailureInfo = new PKIFailureInfo(new ReasonFlags(1 << 22));
            break;

        }
        case ErrorMessages.JKS_FILE_NOT_FOUND:
        case ErrorMessages.NO_SUCH_PROVIDER:
        default: {
            pKIFreeText = new PKIFreeText(new DERUTF8String(ErrorMessages.UNEXPECTED_ERROR));
            pKIFailureInfo = new PKIFailureInfo(new ReasonFlags(1 << 23));
            break;
        }

        }
        errorStatusInfo = new PKIStatusInfo(pKIStatus, pKIFreeText, pKIFailureInfo);
        return errorStatusInfo;
    }

}
