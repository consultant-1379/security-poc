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

import java.io.IOException;

import javax.naming.InvalidNameException;

import org.bouncycastle.asn1.cmp.*;
import org.bouncycastle.asn1.crmf.CertReqMsg;
import org.bouncycastle.asn1.crmf.CertTemplate;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.RequestMessage;
import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.MessageParsingException;
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility;

/**
 * This is an utility class which handles Certificate related operations.
 * 
 * @author tcsramc
 *
 */
public class CertificateUtility {
    private CertificateUtility() {

    }

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateUtility.class);

    /**
     * This method is used to get SerialNumber from the certificate based on the message given.
     * 
     * @param messageBytes
     *            from the Certificate serial number has to be fetched.
     * @return certificate SerialNumber.
     * @throws MessageParsingException
     *             is thrown if any message parsing exception occurs.
     * @throws IOException
     *             is thrown if an I/O error occurs.
     */
    public static String getCertificateSerialNumber(final byte[] messageBytes) throws MessageParsingException, IOException {
        LOGGER.info("Extracting the certificate serial number from the request message");
        final PKIMessage pKIMessage = PKIMessageUtil.pKIMessageFromByteArray(messageBytes);
        String serialNumber = null;

        switch (pKIMessage.getBody().getType()) {
        case PKIBody.TYPE_KEY_UPDATE_REQ: {
            final RequestMessage requestMessage = new RequestMessage(messageBytes);
            serialNumber = Long.toHexString(requestMessage.getUserCertificate().getSerialNumber().longValue());
            break;
        }

        case PKIBody.TYPE_INIT_REP:
        case PKIBody.TYPE_KEY_UPDATE_REP: {
            final CMPCertificate certificate = getCMPCertificate(pKIMessage);
            serialNumber = Long.toHexString(certificate.getX509v3PKCert().getSerialNumber().getPositiveValue().longValue());
            break;
        }

        default: {
            LOGGER.warn("Unknown Message type while extracting serial Number from Message bytes");
        }

        }

        return serialNumber;
    }

    /**
     * This method is used to return the issuer name from the certificate.
     * 
     * @param messageBytes
     *            from which issuername has to be fetched.
     * @return issuerName
     * @throws MessageParsingException
     *             is thrown if any message parsing exception occurs.
     * @throws IOException
     *             is thrown if an I/O error occurs.
     * @throws InvalidNameException
     *             is thrown if any error occurs while parsing the names.
     */
    public static String getCertificateIssuer(final byte[] messageBytes) throws MessageParsingException, IOException, InvalidNameException {
        LOGGER.info("Getting the Issuer name from the certificate");
        final PKIMessage pKIMessage = PKIMessageUtil.pKIMessageFromByteArray(messageBytes);
        String issuerName = null;

        switch (pKIMessage.getBody().getType()) {
        case PKIBody.TYPE_KEY_UPDATE_REQ: {
            final RequestMessage requestMessage = new RequestMessage(messageBytes);
            final String cNissuerName = requestMessage.getUserCertificate().getIssuerDN().getName();
            issuerName = StringUtility.getCNfromDN(cNissuerName);
            break;
        }

        case PKIBody.TYPE_INIT_REP:
        case PKIBody.TYPE_KEY_UPDATE_REP: {
            final CMPCertificate certificate = getCMPCertificate(pKIMessage);
            issuerName = certificate.getX509v3PKCert().getIssuer().toString();
            break;
        }
        default: {
            LOGGER.warn("Unknown Message type while extracting issuerName from Message bytes");
        }
        }

        return issuerName;
    }

    public static String fetchSubjectNameFromPKIMessage(final PKIMessage pKIMessage) {

        final CertReqMsg certReqMsg = PKIMessageUtil.getCertReqMsg(pKIMessage);
        final CertTemplate certTemplate = certReqMsg.getCertReq().getCertTemplate();
        return certTemplate.getSubject().toString();

    }

    private static CMPCertificate getCMPCertificate(final PKIMessage pKIMessage) {
        final CertRepMessage ipMessage = CertRepMessage.getInstance(pKIMessage.getBody().getContent());
        final CertResponse[] certResponses = ipMessage.getResponse();
        final CertResponse resp = certResponses[0];
        return  resp.getCertifiedKeyPair().getCertOrEncCert().getCertificate();
    }

}
