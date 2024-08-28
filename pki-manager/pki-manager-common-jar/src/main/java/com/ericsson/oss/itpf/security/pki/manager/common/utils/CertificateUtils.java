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

package com.ericsson.oss.itpf.security.pki.manager.common.utils;

import java.io.IOException;
import java.math.BigDecimal;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.crmf.CertificateRequestMessage;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;

import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.Certificate;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CRMFRequestHolder;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.persistence.entities.CertificateData;

/**
 * This class is used to convert list of Certificates to list of X509Certificates.
 * 
 * @author tcsramc
 * 
 */
public class CertificateUtils {
    private CertificateUtils() {

    }

    /**
     * This method converts list of Certificates to X509Certificates
     * 
     * @param certificates
     *            list of Certificates to convert
     * @return returns list of X509Certificates
     * 
     */
    public static List<X509Certificate> convert(final List<Certificate> certificates) {
        final List<X509Certificate> x509Certificates = new ArrayList<X509Certificate>();

        for (final Certificate certificate : certificates) {
            x509Certificates.add(certificate.getX509Certificate());
        }

        return x509Certificates;
    }

    /**
     * This method converts given certificate in bytes to X509Certificate
     * 
     * @param certificateAsBytes
     *            {@link CertificateData} object in bytes
     * 
     * @return X509Certificate object
     * @throws CertificateException
     *             thrown if any exception arises in certificateData object conversion to X509 certificate
     * @throws IOException
     *             thrown if failed or interrupted IOException occurs
     */
    public static X509Certificate convert(final byte[] certificateAsBytes) throws CertificateException, IOException {
        final X509CertificateHolder certificateHolder = new X509CertificateHolder(certificateAsBytes);
        final X509Certificate x509Certificate = new JcaX509CertificateConverter().setProvider(Constants.PROVIDER_NAME).getCertificate(certificateHolder);
        return x509Certificate;
    }

    /**
     * To get Subject Fields from Certificate Request
     * @param certificateRequest
     *            PKCS10/CRMF certificate request
     * @return List of SubjectFields
     * @throws IllegalArgumentException
     *             Thrown when Unsupported SubjectFieldType found in Certificate Request
     */
    public static List<SubjectField> getSubjectFieldsFromCertificateRequest(final CertificateRequest certificateRequest)
            throws IllegalArgumentException {
        X500Name certificateRequestSubject = null;
        Subject certificationRequestSubject = new Subject();
        if (certificateRequest.getCertificateRequestHolder() != null) {

            if (certificateRequest.getCertificateRequestHolder() instanceof PKCS10CertificationRequestHolder) {
                final PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = (PKCS10CertificationRequestHolder) certificateRequest
                        .getCertificateRequestHolder();
                final PKCS10CertificationRequest pkcs10CertificationRequest = pkcs10CertificationRequestHolder.getCertificateRequest();
                certificateRequestSubject = pkcs10CertificationRequest.getSubject();
            } else {
                final CRMFRequestHolder crmfRequestHolder = (CRMFRequestHolder) certificateRequest.getCertificateRequestHolder();
                final CertificateRequestMessage crmfCertificationRequest = crmfRequestHolder.getCertificateRequest();
                certificateRequestSubject = crmfCertificationRequest.getCertTemplate().getSubject();
            }

           certificationRequestSubject = new Subject().fromASN1String(certificateRequestSubject.toString());
        }
        return certificationRequestSubject.getSubjectFields();
    }

    /**
     * Converts the Certificate serial number from decimal to Hexadecimal format
     *
     * @param serialNumber
     *            in decimal format
     * @return serialNumber in hexadecimal format
     */
    public static String convertCertSerialNumberToHex(final String serialNumber) {
        String hexaDecimalSerialNumber = null;
        try {
            hexaDecimalSerialNumber = new BigDecimal(serialNumber).toBigInteger().toString(16);
        } catch (final NumberFormatException e) {
            hexaDecimalSerialNumber = serialNumber;
        }
        return hexaDecimalSerialNumber;
    }
}
