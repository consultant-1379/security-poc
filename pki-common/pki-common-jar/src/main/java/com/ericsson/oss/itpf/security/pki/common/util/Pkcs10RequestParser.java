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
package com.ericsson.oss.itpf.security.pki.common.util;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.pkcs.Attribute;
import org.bouncycastle.asn1.pkcs.PKCSObjectIdentifiers;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.common.util.exception.OTPNotFoundInCSRException;

/**
 * Pkcs10RequestParser will retrieve the attributes from PKCS10CertificationRequest. The Attributes likes Challenge password and Subject Name which are present in the certification request are
 * extracted.
 * 
 * @author xananer
 */
public class Pkcs10RequestParser {

    private static final Logger logger = LoggerFactory.getLogger(Pkcs10RequestParser.class);

    /**
     * This method extracts challenge password from the PKCS10CertificationRequest.
     * 
     * @param PKCS10CertificationRequest
     *            PKCS10Request which is the Certificate Signing Request.
     * 
     * @return String Challenge Password is the challenge password from PKCS10CertificationRequest or null if it is not exist in the request.
     * @throws IllegalAttributeException
     *             is thrown if the invalid attribute in the PKCS10CertificationRequest.
     */
    public String getPassword(final PKCS10CertificationRequest pkcs10CertificationRequest) {
        logger.info("Start of getPassword method in Pkcs10RequestParser");
        String pwd = null;

        final Attribute[] attributes = pkcs10CertificationRequest.getAttributes();
        if (attributes == null) {
            return null;
        }
        Attribute otpAttr = null;
        for (final Attribute attribute : attributes) {
            if (attribute.getAttrType().equals(PKCSObjectIdentifiers.pkcs_9_at_challengePassword)) {
                otpAttr = attribute;
                break;
            }
        }
        ASN1Encodable obj = null;
        if (otpAttr == null) {
            logger.error("OTP is not found in the CSR");
            throw new OTPNotFoundInCSRException(ErrorMessages.OTP_NOT_FOUND);
        }

        final ASN1Set values = otpAttr.getAttrValues();
        obj = values.getObjectAt(0);

        if (obj != null) {
            ASN1String str = null;

            try {
                str = DERPrintableString.getInstance((obj));
            } catch (final IllegalArgumentException e) {

                logger.debug("Invalid Atrribute in the CSR ", e);
                logger.info("Invalid Atrribute in the CSR");
                str = DERUTF8String.getInstance((values.getObjectAt(0)));

            }
            if (str != null) {
                pwd = str.getString();
            }
        }

        logger.info("End of getPassword method in Pkcs10RequestParser ");
        return pwd;
    }

    /**
     * Returns the string representation of the subject DN from the certification request.
     * 
     * @param PKCS10CertificationRequest
     *            PKCS10Request which is the Certificate Signing Request.
     * 
     * @return subject DN is the Subject Dn from certification request.
     */
    public X500Name getRequestDN(final PKCS10CertificationRequest pkcs10CertificationRequest) {
        logger.info("Start of getRequestDN method in Pkcs10RequestParser class");
        final X500Name name = pkcs10CertificationRequest.getSubject();
        logger.info("End of getRequestDN method in Pkcs10RequestParser class");
        return name;
    }

}
