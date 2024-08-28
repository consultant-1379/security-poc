/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2018
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.ra.cmp.notification;

import java.io.IOException;

import javax.inject.Inject;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.cmp.PKIMessage;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.cmp.model.exception.MessageParsingException;
import com.ericsson.oss.itpf.security.pki.common.cmp.util.CertificateUtility;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.ra.model.edt.CertificateEnrollmentStatusType;
import com.ericsson.oss.itpf.security.pki.ra.model.events.CertificateEnrollmentStatus;

/**
 * This class is to build and dispatch Certificate Enrollment Status.
 * 
 * @author xgvgvgv
 *
 */
public class CertificateEnrollmentStatusUtility {

    @Inject
    CertificateEnrollmentStatusBuilder certificateEnrollmentStatusBuilder;

    @Inject
    CertificateEnrollmentStatusDispatcher certificateEnrollmentStatusDispatcher;

    private static final Logger LOGGER = LoggerFactory.getLogger(CertificateEnrollmentStatusUtility.class);

    /**
     * This method is to build and dispatch certificate enrollment status
     *
     * @param subjectName
     *            the Subject Name in the Certificate Request
     * 
     * @param issuerName
     *            name of the issuer
     *
     * @param errorInfo
     *            error information
     *
     */

    public void buildAndDispatchCertificateEnrollmentStatus(final String commonName, final String issuerName, final String errorInfo) {
        CertificateEnrollmentStatus certificateEnrollmentStatus;
        if (!Constants.NO_ERROR_INFO.equals(errorInfo)) {
            certificateEnrollmentStatus = certificateEnrollmentStatusBuilder.build(commonName, issuerName, CertificateEnrollmentStatusType.FAILURE);

        } else {
            certificateEnrollmentStatus = certificateEnrollmentStatusBuilder.build(commonName, issuerName, CertificateEnrollmentStatusType.CERTIFICATE_SENT);
        }
        if (certificateEnrollmentStatus != null) {
            certificateEnrollmentStatusDispatcher.dispatch(certificateEnrollmentStatus);
        }
    }

    /**
     * This method is to extract subjectName from InitialMessage
     *
     * @param initialMessage
     *            content of the initialMessage from the database
     * 
     * @return subjectName
     */

    public String extractSubjectNameFromInitialMessage(final byte[] initialMessage) throws IOException {
        final PKIMessage pKIMessage = pKIMessageFromByteArray(initialMessage);
        return CertificateUtility.fetchSubjectNameFromPKIMessage(pKIMessage);
    }

    private PKIMessage pKIMessageFromByteArray(final byte[] inputByteArray) throws IOException {
        PKIMessage pKIMessage = null;
        final ASN1InputStream inputStream = new ASN1InputStream(inputByteArray);
        try {
            final ASN1Primitive rawMessage = inputStream.readObject();
            pKIMessage = PKIMessage.getInstance(ASN1Sequence.getInstance(rawMessage));
        } catch (IOException ioException) {
            LOGGER.error("Exception occured while building PKIMessage:", ioException);
            throw new MessageParsingException(ErrorMessages.IO_EXCEPTION, ioException);
        } finally {
            inputStream.close();
        }
        return pKIMessage;
    }
}
