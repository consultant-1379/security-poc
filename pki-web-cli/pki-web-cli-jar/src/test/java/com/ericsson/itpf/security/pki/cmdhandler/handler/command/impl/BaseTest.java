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
package com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl;

import java.io.FileInputStream;
import java.io.IOException;
import java.security.cert.*;
import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.itpf.security.pki.cmdhandler.handler.command.impl.util.Constants;
import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.PKCS10CertificationRequestHolder;

public class BaseTest {

    static Logger logger = LoggerFactory.getLogger(BaseTest.class);

    private static String certificate_type = "X.509";
    
    private static String cRL_type = "X.509";

    /**
     * Method to get {@link X509Certificate} from certificate file.
     * 
     * @param filename
     *            name of certificate file.
     * @return X509Certificate object.
     * @throws IOException
     *             {@link IOException}
     * @throws CertificateException
     *             {@link CertificateException}
     */
    public static X509Certificate getCertificate(final String filename) throws IOException, CertificateException {

	final FileInputStream fin = new FileInputStream(filename);
	final CertificateFactory certificateFactory = CertificateFactory.getInstance(certificate_type);
	final X509Certificate certificate = (X509Certificate) certificateFactory.generateCertificate(fin);
	return certificate;
    }

    /**
     * Method to get {@link CSR} from csrData.
     * 
     * @param csrData
     * 
     * @return CSR object.
     * 
     */

    public static CertificateRequest generateCertificateRequest(String csrData) {

	final CertificateRequest certRequest = new CertificateRequest();

	try {
	    PKCS10CertificationRequestHolder pkcs10CertificationRequestHolder = null;

	    csrData = csrData.replace("-----BEGIN CERTIFICATE REQUEST-----" + Constants.NEXT_LINE, "");
	    csrData = csrData.replace(Constants.NEXT_LINE + "-----END CERTIFICATE REQUEST-----" + Constants.NEXT_LINE,
		    "");

	    final byte[] derByteArray = javax.xml.bind.DatatypeConverter.parseBase64Binary(csrData);
	    final PKCS10CertificationRequest certificationRequest = new PKCS10CertificationRequest(derByteArray);

	    pkcs10CertificationRequestHolder = new PKCS10CertificationRequestHolder(certificationRequest);

	    certRequest.setCertificateRequestHolder(pkcs10CertificationRequestHolder);

	} catch (IOException exception) {
	    logger.debug("Error while generating CSR " + exception.getMessage());
	}

	return certRequest;
    }
    
    /**
     * Method to get {@link X509CRL} from CRL file.
     * 
     * @param filename
     *            name of CRL file.
     * @return X509CRL object.
     * @throws IOException
     *             {@link IOException}
     * @throws CertificateException
     *             {@link CertificateException}
     *@throws CRLException
     *             {@link CRLException}             
     */
    
    
    public static X509CRL getCRL(final String filename) throws IOException, CertificateException, CRLException {

        final FileInputStream fin = new FileInputStream(filename);
        final CertificateFactory certificateFactory = CertificateFactory.getInstance(cRL_type);
        final X509CRL cRL = (X509CRL) certificateFactory.generateCRL(fin);
        return cRL;
    } 
    
    
    public static Subject getSubject(final String commonName) {

        final Subject subject = new Subject();

        final List<SubjectField> subjectFields = new ArrayList<SubjectField>();
        final SubjectField commonNameField = new SubjectField();
        commonNameField.setType(SubjectFieldType.COMMON_NAME);
        commonNameField.setValue(commonName);

        final SubjectField organization = new SubjectField();
        organization.setType(SubjectFieldType.ORGANIZATION);
        organization.setValue("ENM");

        final SubjectField organizationUnit = new SubjectField();
        organizationUnit.setType(SubjectFieldType.ORGANIZATION_UNIT);
        organizationUnit.setValue("Ericsson");

        final SubjectField emailField = new SubjectField();
        emailField.setType(SubjectFieldType.EMAIL_ADDRESS);
        emailField.setValue(commonName + "@mail.com");

        subjectFields.add(commonNameField);
        subjectFields.add(emailField);
        subjectFields.add(organization);
        subjectFields.add(organizationUnit);
        subject.setSubjectFields(subjectFields);

        return subject;

    }

}
