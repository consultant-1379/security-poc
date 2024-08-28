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

import static org.junit.Assert.*;

import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;

import javax.naming.InvalidNameException;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.InvalidSubjectException;

@RunWith(MockitoJUnitRunner.class)
public class SubjectUtilsTest {

    @Test
    public void testCompareDN() {

        final String[] subject = { "O=ericsson", "CN=ARJ_Root5" };
        final SubjectField sf1 = new SubjectField();
        sf1.setType(SubjectFieldType.COMMON_NAME);
        sf1.setValue("ARJ_Root5");
        final SubjectField sf2 = new SubjectField();
        sf2.setType(SubjectFieldType.ORGANIZATION);
        sf2.setValue("ericsson");
        final List<SubjectField> subjectList = new ArrayList<SubjectField>();
        subjectList.add(sf1);
        subjectList.add(sf2);
        final boolean isEqual = SubjectUtils.compareDN(subject, subjectList);
        assertTrue(isEqual);

    }

    @Test
    public void testCompareDN_Fail() {

        final String[] subject = { "C=SE", "OU=enm", "O=ericsson", "CN=ARJ_Root5" };
        final SubjectField sf1 = new SubjectField();
        sf1.setType(SubjectFieldType.COMMON_NAME);
        sf1.setValue("ARJ_Root5");
        final SubjectField sf2 = new SubjectField();
        sf2.setType(SubjectFieldType.ORGANIZATION);
        sf2.setValue("ericsson");
        final List<SubjectField> subjectList = new ArrayList<SubjectField>();
        subjectList.add(sf1);
        subjectList.add(sf2);
        final boolean isEqual = SubjectUtils.compareDN(subject, subjectList);
        assertFalse(isEqual);

    }

    @Test
    public void isDNMatched() {

        final String subject1 = "SERIALNUMBER=1234567, GIVENNAME=foo, T=Swagat, OU=Ericsson, O=TCS, STREET=DLF, ST=Telangana, L=Gachibowli, C=IN, SURNAME=Panigrahi, CN=ENM_Management_CA";
        final String subject2 = "C=IN, SURNAME=Panigrahi, ST=Telangana, L=Gachibowli, CN=ENM_Management_CA, SERIALNUMBER=1234567, GIVENNAME=foo, T=Swagat, OU=Ericsson, O=TCS, STREET=DLF ";
        final boolean isEqual = SubjectUtils.isDNMatched(subject1, subject2);

        assertTrue(isEqual);

    }

    @Test
    public void isDNMatched_Fail() {

        final String subject1 = "SERIALNUMBER=1234567, GIVENNAME=foo, T=Swagat, OU=Ericsson, O=TCS, STREET=DLF, ST=Telangana, L=Gachibowli, C=IN, SURNAME=Panigrahi, CN=ENM_Management_CA";
        final String subject2 = "C=INDIA, SURNAME=Panigrahi, ST=Telangana, L=Gachibowli, CN=ENM_Management_CA, SERIALNUMBER=1234567, GIVENNAME=foo, T=Swagat, OU=Ericsson, O=TCS, STREET=DLF ";
        final boolean isEqual = SubjectUtils.isDNMatched(subject1, subject2);
        assertFalse(isEqual);

    }

    @Test
    public void isDNMatchedMismatch() {

        final String subject1 = "SERIALNUMBER=1234567, GIVENNAME=foo, T=Swagat, OU=Ericsson, O=TCS, STREET=DLF, ST=Telangana, L=Gachibowli, C=IN, SURNAME=Panigrahi, CN=ENM_Management_CA";
        final String subject2 = "CN=ENM_Management_CA, SERIALNUMBER=1234567, GIVENNAME=foo, T=Swagat, OU=Ericsson, O=TCS, STREET=DLF ";
        final boolean isEqual = SubjectUtils.isDNMatched(subject1, subject2);
        assertFalse(isEqual);

    }

    @Test(expected = InvalidSubjectException.class)
    public void isDNMatchedThrowsInvalidCertificateRequestException() {

        final String subject1 = "test";
        final String subject2 = "C=IN, SURNAME=Panigrahi, ST=Telangana, L=Gachibowli, CN=ENM_Management_CA, SERIALNUMBER=1234567, GIVENNAME=foo, T=Swagat, OU=Ericsson, O=TCS, STREET=DLF ";
        final boolean isEqual = SubjectUtils.isDNMatched(subject1, subject2);
        assertFalse(isEqual);
    }

    @Test
    public void testOrderSubjectDN() {
        final String subject = "C=CN,L=Genova,ST=Italy";
        final String subjectExpected = "C=CN,L=Genova,ST=Italy";
        final String subject1 = "C=CN,CN=com,DN=dn";
        final String subject1Expected = "CN=com,C=CN,DN=dn";
        final String subject2 = "ST=Italy,SURNAME=SN,STREET=Contore";
        final String subject2Expected = "SURNAME=SN,ST=Italy,STREET=Contore";
        final String subject3 = "OU=ou,O=sdf";
        final String subject3Expected = "O=sdf,OU=ou";
        final String subject4 = "SN=serial,CN=com,DN=dn";
        final String subject4Expected = "CN=com,DN=dn,SN=serial";
        final String subject5 = "L=Genova,ST=Italy,SURNAME=SN";
        final String subject5Expected = "SURNAME=SN,L=Genova,ST=Italy";
        final String subject6 = "C=CN,L=Genova,ST=Italy,SURNAME=SN,STREET=Contore";
        final String subject6Expected = "SURNAME=SN,C=CN,L=Genova,ST=Italy,STREET=Contore";
        final String subject7 = "C=CN,L=Genova,SURNAME=SN,STREET=Contore";
        final String subject7Expected = "SURNAME=SN,C=CN,L=Genova,STREET=Contore";
        final String subject8 = "T=tir,L=Genova,SURNAME=SN,STREET=Contore";
        final String subject8Expected = "SURNAME=SN,L=Genova,STREET=Contore,T=tir";
        final String subject9 = "T=tir,L=Genova,SURNAME=SN,STREET=Contore,T=tir";
        final String subject9Expected = "SURNAME=SN,L=Genova,STREET=Contore,T=tir,T=tir";
        final String subject10 = "OU=ou,O=sdf,STREET=Contore";
        final String subject10Expected = "STREET=Contore,O=sdf,OU=ou";
        final String subject11 = "L=Genova,OU=ou,O=sdf";
        final String subject11Expected = "L=Genova,O=sdf,OU=ou";
        final String subject12 = "C=CN,CN=com,STREET=Contore";
        final String subject12Expected = "CN=com,C=CN,STREET=Contore";
        final String subject13 = "C=CN,SURNAME=SN,GIVENNAME=GN";
        final String subject13Expected = "SURNAME=SN,C=CN,GIVENNAME=GN";
        final String subject14 = "C=CN,SN=serial,DN=dn";
        final String subject14Expected = "C=CN,DN=dn,SN=serial";

        final String subjectDN = SubjectUtils.orderSubjectDN(subject);
        assertEquals(subjectExpected, subjectDN);

        final String subjectDN1 = SubjectUtils.orderSubjectDN(subject1);
        assertEquals(subject1Expected, subjectDN1);

        final String subjectDN2 = SubjectUtils.orderSubjectDN(subject2);
        assertEquals(subject2Expected, subjectDN2);

        final String subjectDN3 = SubjectUtils.orderSubjectDN(subject3);
        assertEquals(subject3Expected, subjectDN3);

        final String subjectDN4 = SubjectUtils.orderSubjectDN(subject4);
        assertEquals(subject4Expected, subjectDN4);

        final String subjectDN5 = SubjectUtils.orderSubjectDN(subject5);
        assertEquals(subject5Expected, subjectDN5);

        final String subjectDN6 = SubjectUtils.orderSubjectDN(subject6);
        assertEquals(subject6Expected, subjectDN6);

        final String subjectDN7 = SubjectUtils.orderSubjectDN(subject7);
        assertEquals(subject7Expected, subjectDN7);

        final String subjectDN8 = SubjectUtils.orderSubjectDN(subject8);
        assertEquals(subject8Expected, subjectDN8);

        final String subjectDN9 = SubjectUtils.orderSubjectDN(subject9);
        assertEquals(subject9Expected, subjectDN9);

        final String subjectDN10 = SubjectUtils.orderSubjectDN(subject10);
        assertEquals(subject10Expected, subjectDN10);

        final String subjectDN11 = SubjectUtils.orderSubjectDN(subject11);
        assertEquals(subject11Expected, subjectDN11);

        final String subjectDN12 = SubjectUtils.orderSubjectDN(subject12);
        assertEquals(subject12Expected, subjectDN12);

        final String subjectDN13 = SubjectUtils.orderSubjectDN(subject13);
        assertEquals(subject13Expected, subjectDN13);

        final String subjectDN14 = SubjectUtils.orderSubjectDN(subject14);
        assertEquals(subject14Expected, subjectDN14);

    }

    @Test
    public void testMatchesDNSuccessCheck() {
        final String testsubject1 = "SERIALNUMBER=123\\,456, GIVENNAME=NAME1\\,NAME2, OU=Ericsson, O=TCS, CN=TestCN1\\, TestCN2";
        final String testsubject2 = "CN=TestCN1\\, TestCN2, SERIALNUMBER=123\\,456, GIVENNAME=NAME1\\,NAME2, OU=Ericsson, O=TCS";

        final boolean isEqual = SubjectUtils.matchesDN(testsubject1, testsubject2);

        assertTrue(isEqual);
    }

    @Test
    public void testMatchesDNFailureCheck() {
        final String testsubject1 = "SERIALNUMBER=123\\,456, GIVENNAME=NAME1\\,NAME2, OU=Ericsson, O=TCS, CN=TestCN1\\, TestCN2";
        final String testsubject2 = "CN=TestCN1\\, TestCN2, SERIALNUMBER=123, GIVENNAME=NAME1\\,NAME2, OU=Ericsson, O=TCS";

        final boolean isEqual = SubjectUtils.matchesDN(testsubject1, testsubject2);

        assertFalse(isEqual);
    }

    @Test
    public void testMatchesDNInvalidSubjectFieldType() {
        final String testsubject1 = "TestSubjectFieldType=123\\,456, GIVENNAME=NAME1\\,NAME2, OU=Ericsson, O=TCS, CN=TestCN1\\, TestCN2";
        final String testsubject2 = "CN=TestCN1\\, TestCN2, SERIALNUMBER=123, GIVENNAME=NAME1\\,NAME2, OU=Ericsson, O=TCS";

        final boolean isEqual = SubjectUtils.matchesDN(testsubject1, testsubject2);

        assertFalse(isEqual);
    }

    @Test
    public void testMatchesDNFailureSizeMismatchCheck() {
        final String testsubject1 = "SERIALNUMBER=123\\,456, GIVENNAME=NAME1\\,NAME2, OU=Ericsson, O=TCS, CN=TestCN1\\, TestCN2";
        final String testsubject2 = "CN=TestCN1\\, TestCN2, GIVENNAME=NAME1\\,NAME2, OU=Ericsson, O=TCS";

        final boolean isEqual = SubjectUtils.matchesDN(testsubject1, testsubject2);

        assertFalse(isEqual);
    }

    @Test(expected = IllegalArgumentException.class)
    public void testMatchesDNNullCheck() {
        final String testsubject1 = "SERIALNUMBER=123\\,456, GIVENNAME=NAME1\\,NAME2, OU=Ericsson, O=TCS, CN=TestCN1\\, TestCN2";
        final String testsubject2 = null;

        final boolean isEqual = SubjectUtils.matchesDN(testsubject1, testsubject2);

        assertFalse(isEqual);
    }

    @Test
    public void testSplitDNs() {
        final String testSubject1 = "C=CN1,CN2,L=Genova,ST=Italy";
        final String testSubject2 = "C=CN1,CN2,O=TestO1,TestO2";

        final String expectedTestSubject1 = "[C=CN1, CN2, L=Genova, ST=Italy]";
        final String expectedTestSubject2 = "[C=CN1, CN2, O=TestO1, TestO2]";

        assertEquals(expectedTestSubject1, Arrays.toString(SubjectUtils.splitDNs(testSubject1)));
        assertEquals(expectedTestSubject2, Arrays.toString(SubjectUtils.splitDNs(testSubject2)));
    }
}
