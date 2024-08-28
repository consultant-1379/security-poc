/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2016
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/
package com.ericsson.oss.itpf.security.pki.manager.common.utils;

import java.security.NoSuchAlgorithmException;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;
import javax.security.auth.x500.X500Principal;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import org.bouncycastle.asn1.x500.style.X500NameTokenizer;

import com.ericsson.oss.itpf.security.pki.common.model.*;
import com.ericsson.oss.itpf.security.pki.common.util.StringUtility;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.configuration.algorithm.AlgorithmNotFoundException;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;

/**
 * This class is used to compare two DN values.
 *
 * @author xramdag
 *
 */
public class SubjectUtils {

    private  static final Map<String, String> bouncyCastleSubjectOidMap = new HashMap<>();

    static {
        bouncyCastleSubjectOidMap.put("DN", "2.5.4.46");
        bouncyCastleSubjectOidMap.put("DNQ", "2.5.4.46");
        bouncyCastleSubjectOidMap.put("DNQUALIFIER", "2.5.4.46");
        bouncyCastleSubjectOidMap.put("SN", "2.5.4.5");
        bouncyCastleSubjectOidMap.put("T", "2.5.4.12");
        bouncyCastleSubjectOidMap.put("TITLE", "2.5.4.12");
        bouncyCastleSubjectOidMap.put("GIVENNAME", "2.5.4.42");
        bouncyCastleSubjectOidMap.put("GN", "2.5.4.42");
    }


    private SubjectUtils() {
    }

    private static final Logger LOGGER = LoggerFactory.getLogger(SubjectUtils.class);

    /**
     * This method is used to compare two DN values. If two DN values are equal then this method will return true else it will return false.
     *
     * @param subject
     *            - String array - To Store different fields of SubjectDN
     * @param subjectList
     *            - List contains - {@link SubjectField}
     *
     * @return - boolean - true or false
     */
    public static boolean compareDN(final String[] subject, final List<SubjectField> subjectList) {
        LOGGER.debug("Comparing two DN values ");
        int counter = 0;
        boolean foundEqualObject = false;
        if (subject.length != subjectList.size()) {
            return false;
        }
        for (final SubjectField certSubjectField : subjectList) {
            for (final String subjectField : subject) {
                final Pattern pattern = Pattern.compile("(.+)(=)(.+)");
                final Matcher matcher = pattern.matcher(subjectField);
                if (matcher.find()) {
                    if (matcher.group(1).trim().equals(certSubjectField.getType().getValue()) && matcher.group(3).trim().equals(certSubjectField.getValue())) {
                        counter++;
                        break;
                    }
                }
            }
        }
        if (counter == subjectList.size()) {
            foundEqualObject = true;
        }
        LOGGER.debug("DN values are equal : {}", foundEqualObject);
        return foundEqualObject;
    }

    /**
     * This method is used to compare two DN values using OidDN. If two DN values are equal then this method will return true else it will return false.
     *
     * @param distinguishedName1
     *            - String- given distinguished name
     * @param distinguishedName2
     *            - String- the distinguished name to be compared
     *
     * @return - boolean - returns true if both the DNs are equal.
     *
     */
    public static boolean matchesDN(final String distinguishedName1, final String distinguishedName2) {
        if (distinguishedName1 == null || distinguishedName2 == null) {
            throw new IllegalArgumentException(String.format("Invalid DN : [%s] : [%s]", distinguishedName1, distinguishedName2));
        }
        try {
            String nameDn1 = getOidDN(distinguishedName1);
            String nameDn2 = getOidDN(distinguishedName2);
            final List<Rdn> rdn1 = new LdapName(nameDn1).getRdns();
            final List<Rdn> rdn2 = new LdapName(nameDn2).getRdns();
            if (rdn1.size() != rdn2.size()) {
                return false;
            }
            return rdn1.containsAll(rdn2);
        } catch (InvalidNameException | IllegalArgumentException e) {
             String errorMessage = "InvalidNameException or IllegalArgumentException raised while matching DN: " + e.getMessage();
             LOGGER.error(errorMessage);
             return false;
        }
    }

    /**
     * This method is used to compare two DN values. If two DN values are equal then this method will return true else it will return false.
     *
     * @param DN1
     *            - String- given distinguished name
     * @param DN2
     *            - String- the distinguished name to be compared
     *
     * @return - boolean - returns true if both the DNs are equal.
     * 
     * @throws InvalidCertificateRequestException
     *             thrown if a given distinguished name is not valid
     */
    public static boolean isDNMatched(final String DN1, final String DN2) throws InvalidSubjectException {
        List<Rdn> DN1List = null, DN2List = null;

        LOGGER.debug("Comparing Distinguished Names Input-1: {} Input-2: {}", DN1, DN2);
        try {
            DN1List = new LdapName(DN1).getRdns();
            DN2List = new LdapName(DN2).getRdns();
        } catch (InvalidNameException exception) {
            LOGGER.error("The input distinguised name is not valid : ", exception.getMessage());
            throw new InvalidSubjectException("The input distinguised name is not valid :" + exception.getMessage());
        }
        if (DN1List.size() != DN2List.size()) {
            LOGGER.debug("The given Distinguished Names doesn't match. Different number of RDNs in the DN");
            return false;
        }
        final Set<Object> issuerDNSet = new HashSet<Object>();
        issuerDNSet.addAll(DN1List);

        final Set<Object> issuerSubjectDNSet = new HashSet<Object>();
        issuerSubjectDNSet.addAll(DN2List);

        final boolean isMatched = issuerDNSet.equals(issuerSubjectDNSet);
        if (isMatched) {
            LOGGER.debug("The given Distinguished Names successfully Matched");
        } else {
            LOGGER.debug("The given Distinguished Names doesn't match");
        }
        return isMatched;
    }

    /**
     * This method is used to generate the hash for the subject DN of the entity.
     *
     * @param subjectDN
     *            Subject DN of the entity
     * @return hash of the subject DN
     *
     * @throws AlgorithmNotFoundException
     *             thrown when the specified algorithm is not supported
     */
    public static byte[] generateSubjectDNHash(final String subjectDN) throws AlgorithmNotFoundException {
        byte[] subjectDNHash = null;
        try {
            subjectDNHash = StringUtility.generateHash(subjectDN, Constants.digestAlgorithm);

        } catch (final NoSuchAlgorithmException noSuchAlgorithmException) {
            LOGGER.error(ErrorMessages.ALGORITHM_IS_NOT_FOUND, "Exception : ", noSuchAlgorithmException.getMessage());
            throw new AlgorithmNotFoundException(ErrorMessages.ALGORITHM_IS_NOT_FOUND + noSuchAlgorithmException);
        }
        return subjectDNHash;
    }

    /**
     * This method is used for reordering the subject field types of the given subjectDN string to the order mentioned in {@link SubjectFieldType} class
     *
     * @param subjectDN
     *            Subject DN of the entity
     * @return ordered subject DN
     */
    public static String orderSubjectDN(final String subjectDN) {
        final StringBuffer orderedSubjectDN = new StringBuffer();

        final ArrayList<Pattern> patternList = new ArrayList<Pattern>();
        for (final SubjectFieldType fieldType : SubjectFieldType.values()) {
            patternList.add(Pattern.compile(" *" + fieldType.getValue() + " *=.*"));
        }

        for (final Pattern pattern : patternList) {
            X500NameTokenizer x500Tokenizer= new X500NameTokenizer(subjectDN , ',');
            String subject = null;

            while (x500Tokenizer.hasMoreTokens()) {
                subject = x500Tokenizer.nextToken();
                final Matcher patternMatcher = pattern.matcher(subject);

                if (patternMatcher.matches()) {
                    orderedSubjectDN.append(subject + ",");
                }
            }
        }
        // Removing the last comma after all the subjects are added
        return orderedSubjectDN.substring(0, orderedSubjectDN.length() - 1);
    }

    /**
     * This method is used for removing the DNQ field from  subjectDN string of the {@link Subject}
     *
     * @param subject
     *
     * TORF-143242 - Removing DNQ from the Certificate unblock the AMOS issue
     *
     */
    public static void removeDNQFromSubject(final Subject subject){
        final Iterator<SubjectField> iterator = subject.getSubjectFields().iterator();
        while (iterator.hasNext()) {
            final SubjectField subjectField = iterator.next();
            if (subjectField.getType().equals(SubjectFieldType.DN_QUALIFIER)) {
                iterator.remove();
            }
        }
    }

    /**
     * This method is used for split DN using comma (,)
     *
     * @param distinguishedName
     *
     * @return String[] of the DN field types
     *
     */
    public static String[] splitDNs(String distinguishedName) {
        X500NameTokenizer x500Tokenizer= new X500NameTokenizer(distinguishedName , ',');
        ArrayList<String> rdnNames= new ArrayList<>();
        while (x500Tokenizer.hasMoreTokens()) {
            rdnNames.add(x500Tokenizer.nextToken());
        }
        return rdnNames.toArray(new String[rdnNames.size()]);
    }

    private static String getOidDN(final String subjectDN) {
        return new X500Principal(subjectDN, bouncyCastleSubjectOidMap).getName(X500Principal.RFC2253, bouncyCastleSubjectOidMap);
    }
}
