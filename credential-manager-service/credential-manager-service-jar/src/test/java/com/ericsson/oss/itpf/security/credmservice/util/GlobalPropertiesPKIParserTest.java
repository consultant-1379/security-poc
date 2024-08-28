package com.ericsson.oss.itpf.security.credmservice.util;

import static org.junit.Assert.assertTrue;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.OutputStream;
import java.util.ArrayList;
import java.util.List;
import java.util.Properties;

import javax.naming.InvalidNameException;
import javax.naming.ldap.LdapName;
import javax.naming.ldap.Rdn;

import org.junit.After;
import org.junit.Before;
import org.junit.Test;

import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.AuthorityKeyIdentifier;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.BasicConstraints;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CRLDistributionPoints;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.CertificateExtensions;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;

public class GlobalPropertiesPKIParserTest {

    @Before
    public void setup() {
        //it creates global.properties file in a relative path and copy in this the content
        //found inside the global.properties of src/test/resources (cause the tested class uses an absolute path)
        final String SHARED_GLOBAL_PROP_FILE = "shared.global.file.properties";

        final Properties configProps = PropertiesReader.getConfigProperties();
        File globe = null;
        final String propFileName = configProps.getProperty(SHARED_GLOBAL_PROP_FILE);
        final InputStream inputStream = getClass().getClassLoader().getResourceAsStream(propFileName);
        try {
            final byte[] buffer = new byte[inputStream.available()];
            inputStream.read(buffer);

            globe = new File(propFileName);
            final OutputStream outStream = new FileOutputStream(globe);
            outStream.write(buffer);

            if (inputStream != null) {
                inputStream.close();
            }
            if (outStream != null) {
                outStream.close();
            }
        } catch (final IOException e) {
            e.printStackTrace();
        }
    }

    @After
    public void deleteResources() {
        final String SHARED_GLOBAL_PROP_FILE = "shared.global.file.properties";

        final Properties configProps = PropertiesReader.getConfigProperties();
        final String propFileName = configProps.getProperty(SHARED_GLOBAL_PROP_FILE);
        final File globe = new File(propFileName);
        final boolean result = globe.delete();
        if (!result) {
            System.out.println("Could have not been able to delete global properties file " + propFileName);
        }
    }

    @Test
    public void sed_EP_Test() {

        LdapName ldapTestMain = null;
        ldapTestMain = GlobalPropertiesPKIParser.getPKI_EntityProfile_DN();
        final List<SubjectField> list1 = GlobalPropertiesPKIParser.fromLdapNameToSubjectFieldList(null);
        assertTrue(list1.equals(new ArrayList<SubjectField>()));

        final List<Rdn> rdnListFail1 = new ArrayList<Rdn>();
        final LdapName ldapTestFail1 = new LdapName(rdnListFail1);
        final List<SubjectField> list2 = GlobalPropertiesPKIParser.fromLdapNameToSubjectFieldList(ldapTestFail1);
        assertTrue(list2.equals(new ArrayList<SubjectField>()));

        final List<SubjectField> listMain = GlobalPropertiesPKIParser.fromLdapNameToSubjectFieldList(ldapTestMain);
        assertTrue(!listMain.isEmpty());
        System.out.println(listMain.toString());

        final List<SubjectField> list4 = GlobalPropertiesPKIParser.mergeSEDAndEP(null, null);
        assertTrue(list4.equals(new ArrayList<SubjectField>()));

        final List<SubjectField> list5 = GlobalPropertiesPKIParser.mergeSEDAndEP(list2, null);
        assertTrue(list5.equals(new ArrayList<SubjectField>()));

        final List<SubjectField> list6 = GlobalPropertiesPKIParser.mergeSEDAndEP(null, list2);
        assertTrue(list6.equals(new ArrayList<SubjectField>()));

        final List<SubjectField> list7 = GlobalPropertiesPKIParser.mergeSEDAndEP(list2, list2); //empty lists as arguments
        assertTrue(list7.equals(new ArrayList<SubjectField>()));

        final List<SubjectField> FilledList1 = new ArrayList<SubjectField>();
        final SubjectField subFieldTitle = new SubjectField();
        subFieldTitle.setType(SubjectFieldType.TITLE);
        subFieldTitle.setValue("pippoTitle");
        FilledList1.add(subFieldTitle);

        final List<SubjectField> list8 = GlobalPropertiesPKIParser.mergeSEDAndEP(null, FilledList1);
        assertTrue(list8.equals(FilledList1));

        final List<SubjectField> list9 = GlobalPropertiesPKIParser.mergeSEDAndEP(FilledList1, null);
        assertTrue(list9.equals(FilledList1));

        final List<SubjectField> list10 = GlobalPropertiesPKIParser.mergeSEDAndEP(list2, FilledList1);
        assertTrue(list10.equals(FilledList1));

        final List<SubjectField> list11 = GlobalPropertiesPKIParser.mergeSEDAndEP(FilledList1, list2);
        assertTrue(list11.equals(FilledList1));

        final List<SubjectField> list12 = GlobalPropertiesPKIParser.mergeSEDAndEP(FilledList1, FilledList1);
        assertTrue(list12.equals(FilledList1));

        final List<SubjectField> list13 = GlobalPropertiesPKIParser.mergeSEDAndEP(listMain, FilledList1); //subfieldtypes mutually exclusive
        assertTrue(list13.containsAll(listMain));
        assertTrue(list13.containsAll(FilledList1));

        final SubjectField subFieldCountryName = new SubjectField();
        subFieldCountryName.setType(SubjectFieldType.COUNTRY_NAME);
        subFieldCountryName.setValue("UK");
        FilledList1.add(subFieldCountryName);
        final List<SubjectField> list14 = GlobalPropertiesPKIParser.mergeSEDAndEP(listMain, FilledList1); //subfieldtypes not mutually exclusive
        assertTrue(list14.containsAll(listMain));//sed always wins, so field with same type in output list
        assertTrue(!list14.containsAll(FilledList1));//will not be from entity profile

        final List<SubjectField> listMain2 = GlobalPropertiesPKIParserTest.FillSubject();
        final List<SubjectField> list15 = GlobalPropertiesPKIParser.mergeSEDAndEP(listMain2, FilledList1);
        assertTrue(list15.containsAll(listMain2));
        assertTrue(!list15.containsAll(FilledList1));

    }

    @Test
    public void fromLdapNameToSubjectFieldListTest() throws InvalidNameException {
        final List<Rdn> rdnListTest = new ArrayList<Rdn>();
        final Rdn rdnSurname = new Rdn("SURNAME", "surname");
        rdnListTest.add(rdnSurname);
        final Rdn rdnCountry = new Rdn("C", "countryname");
        rdnListTest.add(rdnCountry);
        final Rdn rdnLocality = new Rdn("L", "locality");
        rdnListTest.add(rdnLocality);
        final Rdn rdnState = new Rdn("ST", "state");
        rdnListTest.add(rdnState);
        final Rdn rdnOrganization = new Rdn("O", "organization");
        rdnListTest.add(rdnOrganization);
        final Rdn rdnOrgUnit = new Rdn("OU", "organizationunit");
        rdnListTest.add(rdnOrgUnit);
        final Rdn rdnDnQual = new Rdn("DN", "dnqualifier");
        rdnListTest.add(rdnDnQual);
        final Rdn rdnStreeAddr = new Rdn("STREET", "streetaddress");
        rdnListTest.add(rdnStreeAddr);
        final Rdn rdnTitle = new Rdn("T", "title");
        rdnListTest.add(rdnTitle);
        final Rdn rdnGivenName = new Rdn("GIVENNAME", "givenname");
        rdnListTest.add(rdnGivenName);
        final Rdn rdnSerialNumber = new Rdn("SN", "serialnumber");
        rdnListTest.add(rdnSerialNumber);
        final Rdn rdnCommonName = new Rdn("CN", "commonname"); //only for coverage, it will never be read from sed file
        rdnListTest.add(rdnCommonName);

        final LdapName ldapTest = new LdapName(rdnListTest);
        final List<SubjectField> resultSubj = GlobalPropertiesPKIParser.fromLdapNameToSubjectFieldList(ldapTest);

        //  assertTrue(resultSubj.get(0).getValue().equals("surname"));
        assertTrue(resultSubj.get(0).getValue().equals("countryname"));
        //assertTrue(resultSubj.get(1).getValue().equals("locality"));
        //assertTrue(resultSubj.get(2).getValue().equals("state"));
        assertTrue(resultSubj.get(1).getValue().equals("organization"));
        assertTrue(resultSubj.get(2).getValue().equals("organizationunit"));
        //  assertTrue(resultSubj.get(6).getValue().equals("dnqualifier"));
        //assertTrue(resultSubj.get(5).getValue().equals("streetaddress"));
        //assertTrue(resultSubj.get(6).getValue().equals("title"));
        //assertTrue(resultSubj.get(7).getValue().equals("givenname"));
        //assertTrue(resultSubj.get(8).getValue().equals("serialnumber"));
        assertTrue(resultSubj.get(3).getValue().equals("commonname"));

    }

    @Test
    public void mergeLdapTest() {
        LdapName ldapTestMain = null;
        ldapTestMain = GlobalPropertiesPKIParser.getPKI_EntityProfile_DN();
        final LdapName ldapTestFail1 = GlobalPropertiesPKIParser.mergeDN(null, null);
        assertTrue(ldapTestFail1 == null);
        final LdapName ldapTestFail2 = GlobalPropertiesPKIParser.mergeDN(null, ldapTestMain);
        assertTrue(ldapTestFail2.equals(ldapTestMain));
        final LdapName ldapTestFail3 = GlobalPropertiesPKIParser.mergeDN(ldapTestMain, null);
        assertTrue(ldapTestFail3.equals(ldapTestMain));

        final List<Rdn> rdnList = new ArrayList<Rdn>();
        final LdapName ldapTestFill = new LdapName(rdnList);
        final LdapName ldapTestFail4 = GlobalPropertiesPKIParser.mergeDN(ldapTestMain, ldapTestFill);
        assertTrue(ldapTestFail4.equals(ldapTestMain));
        final LdapName ldapTestFail5 = GlobalPropertiesPKIParser.mergeDN(ldapTestFill, ldapTestMain);
        assertTrue(ldapTestFail5.equals(ldapTestMain));

        try {
            final Rdn rdnEntry1 = new Rdn("T", "pippoTitle");
            final Rdn rdnEntry2 = new Rdn("C", "pippoCountry");
            rdnList.add(rdnEntry1);
            rdnList.add(rdnEntry2);
        } catch (final InvalidNameException e) {
        }
        final LdapName ldapTestFill1 = new LdapName(rdnList);
        final LdapName ldapTest5 = GlobalPropertiesPKIParser.mergeDN(ldapTestMain, ldapTestFill1);
        assertTrue(!ldapTest5.equals(ldapTestMain));
        assertTrue(!ldapTest5.equals(ldapTestFill1));

    }

    @Test
    public void compareProfilesCertGenerationTest() {
        CertificateProfile cp1 = null;
        CertificateProfile cp2 = null;
        assertTrue(GlobalPropertiesPKIParser.compareProfilesCertGeneration(cp1, cp2));
        final TrustProfile tp1 = new TrustProfile();
        assertTrue(GlobalPropertiesPKIParser.compareProfilesCertGeneration(tp1, cp2));
        cp1 = new CertificateProfile();
        cp2 = new CertificateProfile();
        assertTrue(GlobalPropertiesPKIParser.compareProfilesCertGeneration(cp1, cp2));
        assertTrue(GlobalPropertiesPKIParser.compareProfilesCertGeneration(tp1, cp1));
        final TrustProfile tp2 = new TrustProfile();
        assertTrue(GlobalPropertiesPKIParser.compareProfilesCertGeneration(tp1, tp2));
        cp1.setCertificateExtensions(new CertificateExtensions());
        assertTrue(!GlobalPropertiesPKIParser.compareProfilesCertGeneration(cp1, cp2));
        cp2.setCertificateExtensions(new CertificateExtensions());
        cp1.setCertificateExtensions(null);
        assertTrue(!GlobalPropertiesPKIParser.compareProfilesCertGeneration(cp1, cp2));
        cp1.setCertificateExtensions(new CertificateExtensions());
        assertTrue(GlobalPropertiesPKIParser.compareProfilesCertGeneration(cp1, cp2));

        //Actual CDPS extension presence test
        final BasicConstraints ext1 = new BasicConstraints();
        cp1.getCertificateExtensions().getCertificateExtensions().add(ext1);
        assertTrue(GlobalPropertiesPKIParser.compareProfilesCertGeneration(cp1, cp2));
        final CRLDistributionPoints ext2 = new CRLDistributionPoints();
        cp1.getCertificateExtensions().getCertificateExtensions().add(ext2);
        assertTrue(!GlobalPropertiesPKIParser.compareProfilesCertGeneration(cp1, cp2));
        final AuthorityKeyIdentifier ext1a = new AuthorityKeyIdentifier();
        cp2.getCertificateExtensions().getCertificateExtensions().add(ext1a);
        assertTrue(!GlobalPropertiesPKIParser.compareProfilesCertGeneration(cp1, cp2));
        final CRLDistributionPoints ext2a = new CRLDistributionPoints();
        cp2.getCertificateExtensions().getCertificateExtensions().add(ext2a);
        assertTrue(GlobalPropertiesPKIParser.compareProfilesCertGeneration(cp1, cp2));

    }

    @Test
    public void skimSubjectTest() {
        assertTrue(GlobalPropertiesPKIParser.skimSubject(null, null).isEmpty());
        assertTrue(GlobalPropertiesPKIParser.skimSubject(new ArrayList<SubjectField>(), null).isEmpty());
        assertTrue(GlobalPropertiesPKIParser.skimSubject(null, new ArrayList<SubjectField>()).isEmpty());
        assertTrue(GlobalPropertiesPKIParser.skimSubject(new ArrayList<SubjectField>(), new ArrayList<SubjectField>()).isEmpty());

        final List<SubjectField> cpList1 = new ArrayList<SubjectField>();
        final SubjectField subCN = new SubjectField();
        subCN.setType(SubjectFieldType.COMMON_NAME);
        cpList1.add(subCN);
        final List<SubjectField> sedList1 = GlobalPropertiesPKIParserTest.FillSubject();
        final List<SubjectField> result1 = GlobalPropertiesPKIParser.skimSubject(cpList1, sedList1);
        assertTrue(result1.size() == 1 && result1.get(0).getType().equals(SubjectFieldType.COMMON_NAME) && result1.get(0).getValue().equals("pluto"));

        //not entirely correct(CP doesn't hold values), but for test purposes it's ok
        final List<SubjectField> cpList2 = GlobalPropertiesPKIParserTest.FillSubject();
        final SubjectField subST = new SubjectField();
        subST.setType(SubjectFieldType.STREET_ADDRESS);
        final List<SubjectField> sedList2 = new ArrayList<SubjectField>();
        subST.setValue("street");
        subCN.setValue("commonname");
        sedList2.add(subST);
        sedList2.add(subCN);
        final List<SubjectField> result2 = GlobalPropertiesPKIParser.skimSubject(cpList2, sedList2);
        assertTrue(result2.size() == 2 && result2.get(0).getType().equals(SubjectFieldType.STREET_ADDRESS)
                && result2.get(1).getType().equals(SubjectFieldType.COMMON_NAME) && result2.get(0).getValue().equals("street")
                && result2.get(1).getValue().equals("commonname"));

        //mixed
        final List<SubjectField> cpList3 = new ArrayList<SubjectField>();
        final List<SubjectField> sedList3 = new ArrayList<SubjectField>();
        cpList3.add(subST);
        sedList3.add(subST);
        sedList3.add(subCN);

        final List<SubjectField> result3 = GlobalPropertiesPKIParser.skimSubject(cpList3, sedList3);
        assertTrue(result3.size() == 1 && result3.get(0).getType().equals(SubjectFieldType.STREET_ADDRESS)
                && result3.get(0).getValue().equals("street"));

    }

    private static List<SubjectField> FillSubject() {
        final List<SubjectField> inputList = new ArrayList<SubjectField>();

        final SubjectField subfieldCN = new SubjectField();
        final SubjectField subfieldCoN = new SubjectField();
        final SubjectField subfieldDN = new SubjectField();
        final SubjectField subfieldGN = new SubjectField();
        final SubjectField subfieldLN = new SubjectField();
        final SubjectField subfieldO = new SubjectField();
        final SubjectField subfieldOU = new SubjectField();
        final SubjectField subfieldSN = new SubjectField();
        final SubjectField subfieldST = new SubjectField();
        final SubjectField subfieldSA = new SubjectField();
        final SubjectField subfieldSU = new SubjectField();
        final SubjectField subfieldT = new SubjectField();

        subfieldCN.setType(SubjectFieldType.COMMON_NAME);
        subfieldCN.setValue("pluto");
        subfieldCoN.setType(SubjectFieldType.COUNTRY_NAME);
        subfieldCoN.setValue("ES");
        subfieldDN.setType(SubjectFieldType.DN_QUALIFIER);
        subfieldDN.setValue("pippoQualif");
        subfieldGN.setType(SubjectFieldType.GIVEN_NAME);
        subfieldGN.setValue("p");
        subfieldLN.setType(SubjectFieldType.LOCALITY_NAME);
        subfieldLN.setValue("plutoloc");
        subfieldO.setType(SubjectFieldType.ORGANIZATION);
        subfieldO.setValue("plutoOrg");
        subfieldOU.setType(SubjectFieldType.ORGANIZATION_UNIT);
        subfieldOU.setValue("plutoOrgUnit");
        subfieldSN.setType(SubjectFieldType.SERIAL_NUMBER);
        subfieldSN.setValue("372859021");
        subfieldST.setType(SubjectFieldType.STATE);
        subfieldST.setValue("USA");
        subfieldSA.setType(SubjectFieldType.STREET_ADDRESS);
        subfieldSA.setValue("plutoAddr");
        subfieldSU.setType(SubjectFieldType.SURNAME);
        subfieldSU.setValue("dog");
        subfieldT.setType(SubjectFieldType.TITLE);
        subfieldT.setValue("sir");

        inputList.add(subfieldCN);
        inputList.add(subfieldCoN);
        inputList.add(subfieldDN);
        inputList.add(subfieldGN);
        inputList.add(subfieldLN);
        inputList.add(subfieldO);
        inputList.add(subfieldOU);
        inputList.add(subfieldSN);
        inputList.add(subfieldST);
        inputList.add(subfieldSA);
        inputList.add(subfieldSU);
        inputList.add(subfieldT);

        return inputList;

    }

}
