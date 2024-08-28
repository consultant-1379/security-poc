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

import java.io.IOException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.List;
import java.util.regex.Pattern;

import javax.ejb.ScheduleExpression;
import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.bouncycastle.asn1.ASN1ObjectIdentifier;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.AlgorithmIdentifier;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.keystore.KeyStoreType;
import com.ericsson.oss.itpf.security.pki.common.model.PKIGeneralName;
import com.ericsson.oss.itpf.security.pki.common.util.constants.Constants;

/**
 * This class contains common methods for Strings related operations for all PKI security modules.
 * 
 * @author xjagcho
 * 
 */
public class StringUtility {

    private static final Logger LOGGER = LoggerFactory.getLogger(StringUtility.class);

    private StringUtility() {

    }

    /**
     * This method is used to check whether the given string content is BASE64 or not.
     * 
     * @param content
     *            is the content to be checked whether it is in format of BASE64 or not.
     * 
     * @return boolean true, if the content is BASE64. false, if the content is not BASE64.
     */
    public static boolean isBase64(final String content) {
        LOGGER.info("Start of isBase64 method in StringUtility class");
        final Pattern pattern = Pattern.compile(Constants.BASE64_REG_EXP);
        boolean isBase64 = false;
        if (pattern.matcher(content).matches()) {
            isBase64 = true;
        }
        LOGGER.info("End of isBase64 method in StringUtility class");
        return isBase64;
    }

    /**
     * This method gets requested attributetype from DistinguishedName
     * 
     * @param dn
     *            Distinguished Name
     * @param neededAttributeType
     *            Attributetype which has to be fetched from dn.
     * @return returns requested attribute type which is extracted from the DN
     * @throws InvalidNameException
     *             is thrown if syntax errors occurs.
     */
    public static String getAttributeValueFromDN(final String dn, final String neededAttributeType) throws InvalidNameException {
        String result = null;
        final LdapName ldapName = new LdapName(dn);
        final List<Rdn> rdns = ldapName.getRdns();
        for (final Rdn rdn : rdns) {
            if (rdn.getType().equalsIgnoreCase(neededAttributeType)) {
                result = (String) Rdn.escapeValue(rdn.getValue().toString());
                break;
            }
        }
        return result;
    }

    /**
     * This method is used to get CN from Distiguished name.
     * 
     * @param dn
     *            from which CN has to be fetched.
     * @return returns CN from dn.
     * @throws InvalidNameException
     *             is thrown if syntax errors occurs.
     */
    public static String getCNfromDN(final String dn) throws InvalidNameException {
        final String neededAttributeType = Constants.CN_ATTRIBUTE;
        final String result = getAttributeValueFromDN(dn, neededAttributeType);
        return result;
    }

    /**
     * This method is used to generate the AlgorithmIdentifier using the algorithm OID
     * 
     * @param algorithmOID
     *            Algorithm OID from which AlgorithmIdentifier is generated
     * @return Encoded AlgorithmIdentifier
     * @throws IOException
     *             is thrown when any I/O exception occurs during encoding
     */
    public static byte[] toASN1ObjectIdentifier(final String algorithmOID) throws IOException {
        final ASN1ObjectIdentifier objID = new ASN1ObjectIdentifier(algorithmOID);
        final AlgorithmIdentifier algoID = new AlgorithmIdentifier(objID);
        return algoID.getEncoded();
    }

    /**
     * This method is used to convert the string to GeneralName of X509 certificate.
     * 
     * @param name
     *            the string that need to be converted to GeneralName
     * @return GeneralName of X509 certificate
     */
    public static PKIGeneralName toGeneralName(final String name) {
        return new PKIGeneralName(new X500Name(name));
    }

    /**
     * This method is used to set the type of the key store file
     * 
     * @param pIBConfiguredKeyStoreType
     *            the type of the key store stored in PIB
     * @return the keyStoreType
     */
    public static KeyStoreType toKeyStoreType(final String pIBConfiguredKeyStoreType) {
        KeyStoreType keyStoreType = KeyStoreType.JKS;

        if (KeyStoreType.PKCS12.name().equalsIgnoreCase(pIBConfiguredKeyStoreType)) {
            keyStoreType = KeyStoreType.PKCS12;
        }
        return keyStoreType;

    }

    /**
     * This method will return ScheduleExpression using the passed parameter string.
     * 
     * @param schedulerTime
     *            format example: year,month,dayOfMonth,dayOfWeek,hour,minute,second- "*,*,*,*,1,1,0" - which means the schedule time is every day 01:01 hours
     * 
     * @return ScheduleExpression
     */
    public static ScheduleExpression getScheduleExpressionFromString(final String schedulerTime) {
        final ScheduleExpression schedule = new ScheduleExpression();
        final String scheduleTime[] = schedulerTime.split(",");
        schedule.year(scheduleTime[0]);
        schedule.month(scheduleTime[1]);
        schedule.dayOfMonth(scheduleTime[2]);
        schedule.dayOfWeek(scheduleTime[3]);
        schedule.hour(scheduleTime[4]);
        schedule.minute(scheduleTime[5]);
        schedule.second(scheduleTime[6]);
        return schedule;
    }

    /**
     * This method is used to generate Hash for a given String with the specified algorithm
     * 
     * @param string
     *            The string for which the hash need to be generated
     * @param algorithm
     *            Name of the algorithm by which string need to be hashed
     * @return hash value of the string
     * @throws NoSuchAlgorithmException
     *             thrown in the case where
     */
    public static byte[] generateHash(final String string,final String algorithm) throws NoSuchAlgorithmException {
        final MessageDigest messageDigest = MessageDigest.getInstance(algorithm);
        messageDigest.update(string.toLowerCase().getBytes());
        final byte[] hash = messageDigest.digest();
        return hash;
    }

}
