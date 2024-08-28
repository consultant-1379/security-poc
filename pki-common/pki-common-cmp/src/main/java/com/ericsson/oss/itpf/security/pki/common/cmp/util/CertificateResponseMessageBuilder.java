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
package com.ericsson.oss.itpf.security.pki.common.cmp.util;

import java.security.cert.CertificateEncodingException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.DEROctetString;
import org.bouncycastle.asn1.cmp.*;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.CMPCertificateEncodingException;
import com.ericsson.oss.itpf.security.pki.common.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;

/**
 * This class is used to build CertRepMessage for Success and Waiting Scenarios.
 * 
 * @author tcsramc
 * 
 */
public class CertificateResponseMessageBuilder {
    private static final Logger LOGGER = LoggerFactory.getLogger(StringUtility.class);
    private CertificateResponseMessageBuilder() {

    }

    /**
     * 
     * This method builds CertRepMessage based on requestId,trustCerts and UserCertificate.
     * 
     * @param certRequestID
     *            certificate request ID that need to be set
     * @param userCert
     *            User certificate that need to be set
     * @param trustedCerts
     *            trusted certificates that need to be set
     * @return certrepmessage
     * @throws CMPCertificateEncodingException
     *             is thrown if any encoding error occurs
     */
    public static CertRepMessage build(final int certRequestID, final X509Certificate userCert, final List<X509Certificate> trustedCerts) throws CMPCertificateEncodingException {
        LOGGER.info("Building Certificate response message based on requestID [{}] userCert[{}]" ,certRequestID, userCert);
        final int ACCEPTED = 0;
        CertRepMessage certRepMessage = null;
        CMPCertificate[] finalTrustList = null;
        final List<X509Certificate> trustCertsList = new ArrayList<>(trustedCerts);
        try {
            final CertOrEncCert retCert = new CertOrEncCert(new CMPCertificate(org.bouncycastle.asn1.x509.Certificate.getInstance(userCert.getEncoded())));
            final CertifiedKeyPair certifiedKeyPair = new CertifiedKeyPair(retCert);
            final PKIStatusInfo pKIStatusInfo = createPkiStatusInfo(PKIStatus.getInstance(new ASN1Integer(ACCEPTED)));
            final CertResponse certResponse = new CertResponse(new ASN1Integer(certRequestID), pKIStatusInfo, certifiedKeyPair, new DEROctetString(new byte[] {}));

            finalTrustList = CertificateUtility.toCMPCertificateArray(trustCertsList);
            certRepMessage = new CertRepMessage(finalTrustList, new CertResponse[] { certResponse });
        } catch (CertificateEncodingException certEncodeError) {
            LOGGER.error("Error Occured while encoding the certificate");
            throw new CMPCertificateEncodingException(ErrorMessages.CERTIFICATE_ENCODING_ERROR, certEncodeError);
        }

        return certRepMessage;
    }

    /**
     * This method is for building WaitCertRepMessage
     * 
     * @param certRequestID
     *            certificate request ID that need to be set
     * @return CertRepMessage
     */

    public static CertRepMessage buildWaitingCertRepMessage(final int certRequestID) {
        LOGGER.debug("Setting the Certificate request ID :[{}] for certificate response message which is in waiting state", certRequestID);
        CertResponse[] certResponses = new CertResponse[1];
        final CMPCertificate[] caPubs = null;
        final PKIStatus pKIStatus = PKIStatus.getInstance(new ASN1Integer(PKIStatus.WAITING));
        final PKIStatusInfo pKIStatusInfo = createPkiStatusInfo(pKIStatus);
        final ASN1Integer certReqId = new ASN1Integer(certRequestID);
        final CertResponse certResponse = new CertResponse(certReqId, pKIStatusInfo);
        certResponses[0] = certResponse;

        return new CertRepMessage(caPubs, certResponses);

    }

    private static PKIStatusInfo createPkiStatusInfo(final PKIStatus pKIStatus) {
        final PKIStatusInfo pKIStatusInfo = new PKIStatusInfo(pKIStatus);
        return pKIStatusInfo;
    }

}
