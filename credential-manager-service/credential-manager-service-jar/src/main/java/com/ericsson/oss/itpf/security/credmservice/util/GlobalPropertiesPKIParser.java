/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2020
 *
 * The copyright to the computer program(s) herein is the property of
 * Ericsson Inc. The programs may be used and/or copied only with written
 * permission from Ericsson Inc. or in accordance with the terms and
 * conditions stipulated in the agreement/contract under which the
 * program(s) have been supplied.
 *******************************************************************************
 *----------------------------------------------------------------------------*/

package com.ericsson.oss.itpf.security.credmservice.util;

import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CRLDistributionPoints;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtension;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.AbstractProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;

public final class GlobalPropertiesPKIParser {

    private static final Logger log = LoggerFactory.getLogger(GlobalPropertiesPKIParser.class);

    private static final String SHARED_GLOBAL_PROP_FILE = "shared.global.file.properties";
    //TODO Change this value based on SED. Also, this could be inserted in credmservice.properties (to change also global.properties)
    private static final String GLOBAL_DN_ENTRY_DEFAULT_VALUE = "couldbedefinedbyuser";

    private enum GlobalPropertiesSubjectType {
        PKI_EntityProfile_DN_SURNAME("SURNAME"), PKI_EntityProfile_DN_COUNTRY_NAME("C"), PKI_EntityProfile_DN_LOCALITY_NAME(
                "L"), PKI_EntityProfile_DN_STATE("ST"), PKI_EntityProfile_DN_STREET_ADDRESS("STREET"), PKI_EntityProfile_DN_ORGANIZATION(
                        "O"), PKI_EntityProfile_DN_ORGANIZATION_UNIT("OU"), PKI_EntityProfile_DN_DN_QUALIFIER("DN"), PKI_EntityProfile_DN_TITLE(
                                "T"), PKI_EntityProfile_DN_GIVEN_NAME("GIVENNAME"), PKI_EntityProfile_DN_SERIAL_NUMBER("SN");

        private final String subjectAttribute;

        GlobalPropertiesSubjectType(final String str) {
            this.subjectAttribute = str;
        }

        public String getSubjectAttribute() {
            return subjectAttribute;
        }
    }

    public static LdapName getPKI_EntityProfile_DN() {

        LdapName dn = null;
        final Properties configProps = PropertiesReader.getConfigProperties();

        final String propFileName = configProps.getProperty(SHARED_GLOBAL_PROP_FILE);

        try {
            dn = new LdapName("");
            Properties prop = new Properties();

            prop = PropertiesReader.getProperties(propFileName);

            log.info("Loaded global property file " + propFileName);

            for (final GlobalPropertiesSubjectType key : GlobalPropertiesSubjectType.values()) {
                final String readRDN = prop.getProperty(key.toString());
                if (readRDN != null && !readRDN.isEmpty() && !readRDN.equals(GLOBAL_DN_ENTRY_DEFAULT_VALUE)) {
                    final String[] multiRDN = readRDN.split(",|;");

                    for (int i = 0; i < multiRDN.length; ++i) {
                        final Rdn rdn = new Rdn(key.getSubjectAttribute(), multiRDN[i]);
                        dn.add(rdn);
                    }
                }
            }

        } catch (final InvalidNameException e) {
            log.warn("InvalidNameException catch reading and parsing global properties file: " + e);
        }

        return dn;
    }

    public static List<SubjectField> fromLdapNameToSubjectFieldList(final LdapName dn) {
        final List<SubjectField> ldapList = new ArrayList<SubjectField>();
        if (dn != null && !dn.isEmpty()) {

            SubjectField itemList = null;
            final List<Rdn> ldapRdn = dn.getRdns();
            for (final Rdn itemRdn : ldapRdn) {
                itemList = new SubjectField();
                //itemList.setValue(itemRdn.getValue().toString());
                if ((itemRdn.getType().equals("C")) || (itemRdn.getType().equals("O")) || (itemRdn.getType().equals("OU"))
                        || (itemRdn.getType().equals("CN"))) {
                    itemList.setValue(itemRdn.getValue().toString());
                }
                switch (itemRdn.getType()) {
                    case ("C"):
                        itemList.setType(SubjectFieldType.COUNTRY_NAME);
                        break;
                    case ("O"):
                        itemList.setType(SubjectFieldType.ORGANIZATION);
                        break;
                    case ("OU"):
                        itemList.setType(SubjectFieldType.ORGANIZATION_UNIT);
                        break;
                    case ("CN"):
                        itemList.setType(SubjectFieldType.COMMON_NAME); //not defined on global.properties though
                        break;
                    default:
                        //do nothing
                        break;
                }
                //      ldapList.add(itemList);
                if ((itemRdn.getType().equals("C")) || (itemRdn.getType().equals("O")) || (itemRdn.getType().equals("OU"))
                        || (itemRdn.getType().equals("CN"))) {
                    ldapList.add(itemList);
                }
            }
        }
        return ldapList;
    }

    public static List<SubjectField> mergeSEDAndEP(final List<SubjectField> sed, final List<SubjectField> ep) {
        final List<SubjectField> adjEntries = new ArrayList<SubjectField>();

        if ((sed == null || sed.isEmpty()) && (ep == null || ep.isEmpty())) {
            return adjEntries;
        } else if ((sed == null || sed.isEmpty()) && (!ep.isEmpty())) {
            return ep;
        } else if ((ep == null || ep.isEmpty()) && (!sed.isEmpty())) {
            return sed;
        }

        for (final SubjectField entryProfile : ep) {
            boolean found = false;
            for (final SubjectField entrySed : sed) {
                if (entryProfile.getType() == entrySed.getType()) {
                    found = true;
                    break;
                }
            }
            if (!found) {
                adjEntries.add(entryProfile);
            }
        }
        adjEntries.addAll(sed);

        return adjEntries;
    }

    public static LdapName mergeDN(final LdapName so, final LdapName ad) {

        if ((so == null) && (ad == null)) {
            return null;
        }
        if ((so == null || so.size() == 0) && (ad != null)) {
            return ad;
        }
        if ((ad == null || ad.size() == 0) && (so != null)) {
            return so;
        }

        final LdapName outdn = (LdapName) so.clone();

        final List<Rdn> so_rdn = so.getRdns();
        final List<Rdn> ad_rdn = ad.getRdns();

        for (final Rdn a : ad_rdn) {
            boolean found = false;
            for (final Rdn r : so_rdn) {
                if (a.getType() == r.getType()) {
                    found = true;
                    break;
                }

            }
            if (!found) {
                try {
                    log.info("->adding: " + a.getType().toString() + "=" + a.getValue().toString());
                    outdn.add(a.getType().toString() + "=" + a.getValue().toString());

                } catch (final InvalidNameException e) {
                    log.info("InvalidNameException", e);
                }
            }
        }

        return outdn;
    }

    // Certificate profile subject fields are used as capabilities, so the subject list from Sed is skimmed
    public static List<SubjectField> skimSubject(final List<SubjectField> cPList, final List<SubjectField> sedSubjList) {
        final List<SubjectField> result = new ArrayList<SubjectField>();
        if (cPList == null || sedSubjList == null || cPList.isEmpty() || sedSubjList.isEmpty()) {
            return result;
        }

        for (final SubjectField sedInternal : sedSubjList) {
            for (final SubjectField cpInternal : cPList) {
                if (cpInternal.getType().equals(sedInternal.getType())) {
                    result.add(sedInternal);
                    break;
                }
            }
        }

        return result;

    }

    /*
     * return true if compared profiles are equals for specified fields. On false triggers a new certificate generation
     */
    public static <T extends AbstractProfile> boolean compareProfilesCertGeneration(final T profileFromDB, final T profileFromXML) {

        if (profileFromDB == null || profileFromXML == null) {
            log.error("Wrong profile passed to compare");
            return true;
        }
        //profiles must be of the same type
        final Class<? extends AbstractProfile> profileClass = profileFromXML.getClass();
        if (!(profileClass.isInstance(profileFromDB))) {
            log.error("Profile types passed to compare do not match");
            return true;
        }

        if (profileClass == CertificateProfile.class) {
            final CertificateProfile certProfileFromDB = (CertificateProfile) profileFromDB;
            final CertificateProfile certProfileFromXML = (CertificateProfile) profileFromXML;
            //getCertificateExtensions() List<CertificateExtension> is always instantiated, so I do not check for a null pointer there
            if (certProfileFromDB.getCertificateExtensions() == null && certProfileFromXML.getCertificateExtensions() == null) {
                return true;
            } else if ((certProfileFromDB.getCertificateExtensions() == null && certProfileFromXML.getCertificateExtensions() != null)
                    || (certProfileFromDB.getCertificateExtensions() != null && certProfileFromXML.getCertificateExtensions() == null)) {
                return false;
            }
            for (final CertificateExtension dbCertExtension : certProfileFromDB.getCertificateExtensions().getCertificateExtensions()) {
                //check if CDPS extension is present on db
                if (dbCertExtension instanceof CRLDistributionPoints) {
                    for (final CertificateExtension xmlCertExtension : certProfileFromXML.getCertificateExtensions().getCertificateExtensions()) {
                        //check if CDPS extension is also present on XML
                        if (xmlCertExtension instanceof CRLDistributionPoints) {
                            return true;
                        }
                    }
                    //CDPS extension not found in xml but present on db
                    log.info(
                            "Crl Distribution Point extension not present in xml but found in database: certificate profile update will trigger certificate generation");
                    return false;
                }
            }
        }

        //potentially for future uses
        //        else if (profileClass = EntityProfile.class) {
        //
        //        }

        return true;
    }

}
