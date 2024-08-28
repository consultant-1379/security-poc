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
package com.ericsson.oss.itpf.security.pki.common.model;

import static org.junit.Assert.assertEquals;

import java.util.List;
import java.util.ArrayList;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.runners.MockitoJUnitRunner;

import com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase;
import com.ericsson.oss.itpf.security.pki.manager.test.setup.SubjectSetUpData;

/**
 *  This class is used to run Junits for SubjectIdentifier objects in different scenarios
 */
@RunWith(MockitoJUnitRunner.class)
public class SubjectTest extends EqualsTestCase {

    SubjectSetUpData subjectSetUpData = new SubjectSetUpData();

    private Subject testSubject = new Subject();
    private Subject testSubject1 = new Subject();
    private Subject testSubject2 = new Subject();
    private Subject testSubject3 = new Subject();
    private Subject testSubject4 = new Subject();

    private SubjectField testSubjectField1 = new SubjectField();
    private SubjectField testSubjectField2 = new SubjectField();
    private SubjectField testSubjectField3 = new SubjectField();

    private List<SubjectField> testSubjectField = new ArrayList<>();

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase#createInstance ()
     */
    @Override
    protected Object createInstance() {
        final Subject subject = subjectSetUpData.getSubjectForCreate();
        return subject;
    }

    /*
     * (non-Javadoc)
     * 
     * @see com.ericsson.oss.itpf.security.pki.manager.test.EqualsTestCase# createNotEqualInstance()
     */
    @Override
    protected Object createNotEqualInstance() {
        final Subject subject = subjectSetUpData.getSubjectForCreateNotEqual();
        return subject;
    }

    /**
     * This method is not applicable to Subject Object, so overridden with empty definition
     */
    @Override
    @Test
    public final void testWithEachFieldChange() {

    }

    /**
     * This method is not applicable to Subject Object, so overridden with empty definition
     */
    @Override
    @Test
    public void testWithEachFieldNull() {

    }

    @Test
    public void testFromASN1String() {
        final String testDistinguishedName1 = "CN=TestCN1,O=TestO,OU=TestOU";
        final String testDistinguishedName2 = "CN=TestCN1\\, TestCN2, O=TestO, OU=TestOU1\\,TestOU2\\,TestOU3";
        final String testDistinguishedName3 = "CN=\"TestCN1, TestCN2\", O=TestO, OU=\"TestOU1,TestOU2,TestOU3\"";
        final String testDistinguishedName4 = null;

        testSubjectField1.setType(SubjectFieldType.COMMON_NAME);
        testSubjectField2.setType(SubjectFieldType.ORGANIZATION);
        testSubjectField3.setType(SubjectFieldType.ORGANIZATION_UNIT);
        testSubjectField1.setValue("TestCN1");
        testSubjectField2.setValue("TestO");
        testSubjectField3.setValue("TestOU");

        testSubjectField.add(testSubjectField1);
        testSubjectField.add(testSubjectField2);
        testSubjectField.add(testSubjectField3);

        testSubject1.setSubjectFields(testSubjectField);

        assertEquals(testSubject1, testSubject.fromASN1String(testDistinguishedName1));

        testSubjectField.remove(testSubjectField1);
        testSubjectField.remove(testSubjectField2);
        testSubjectField.remove(testSubjectField3);

        testSubjectField1.setType(SubjectFieldType.COMMON_NAME);
        testSubjectField2.setType(SubjectFieldType.ORGANIZATION);
        testSubjectField3.setType(SubjectFieldType.ORGANIZATION_UNIT);
        testSubjectField1.setValue("TestCN1, TestCN2");
        testSubjectField2.setValue("TestO");
        testSubjectField3.setValue("TestOU1,TestOU2,TestOU3");

        testSubjectField.add(testSubjectField1);
        testSubjectField.add(testSubjectField2);
        testSubjectField.add(testSubjectField3);

        testSubject2.setSubjectFields(testSubjectField);

        assertEquals(testSubject2, testSubject.fromASN1String(testDistinguishedName2));

        testSubjectField.remove(testSubjectField1);
        testSubjectField.remove(testSubjectField2);
        testSubjectField.remove(testSubjectField3);

        testSubjectField1.setType(SubjectFieldType.COMMON_NAME);
        testSubjectField2.setType(SubjectFieldType.ORGANIZATION);
        testSubjectField3.setType(SubjectFieldType.ORGANIZATION_UNIT);
        testSubjectField1.setValue("TestCN1, TestCN2");
        testSubjectField2.setValue("TestO");
        testSubjectField3.setValue("TestOU1,TestOU2,TestOU3");

        testSubjectField.add(testSubjectField1);
        testSubjectField.add(testSubjectField2);
        testSubjectField.add(testSubjectField3);

        testSubject3.setSubjectFields(testSubjectField);

        assertEquals(testSubject3, testSubject.fromASN1String(testDistinguishedName3));

        assertEquals(testSubject, testSubject.fromASN1String(testDistinguishedName4));
    }

    @Test
    public void testToASN1String() {
        final String testDistinguishedName1 = "CN=TestCN1,O=TestO,OU=TestOU";
        final String testDistinguishedName2 = "CN=TestCN1\\, TestCN2,O=TestO,OU=TestOU1\\,TestOU2\\,TestOU3";
        final String testDistinguishedName3 = "CN=TestCN1,O=TestO1\\,TestO2,OU=TestOU1\\,TestOU2\\,TestOU3";
        final String testDistinguishedName4 = "";
        final String testDistinguishedName5 = "CN=null,O=null,OU=null";

        testSubjectField1.setType(SubjectFieldType.COMMON_NAME);
        testSubjectField2.setType(SubjectFieldType.ORGANIZATION);
        testSubjectField3.setType(SubjectFieldType.ORGANIZATION_UNIT);
        testSubjectField1.setValue("TestCN1");
        testSubjectField2.setValue("TestO");
        testSubjectField3.setValue("TestOU");

        testSubjectField.add(testSubjectField1);
        testSubjectField.add(testSubjectField2);
        testSubjectField.add(testSubjectField3);

        testSubject1.setSubjectFields(testSubjectField);

        assertEquals(testDistinguishedName1, testSubject1.toASN1String());

        testSubjectField.remove(testSubjectField1);
        testSubjectField.remove(testSubjectField2);
        testSubjectField.remove(testSubjectField3);

        testSubjectField1.setType(SubjectFieldType.COMMON_NAME);
        testSubjectField2.setType(SubjectFieldType.ORGANIZATION);
        testSubjectField3.setType(SubjectFieldType.ORGANIZATION_UNIT);
        testSubjectField1.setValue("TestCN1, TestCN2");
        testSubjectField2.setValue("TestO");
        testSubjectField3.setValue("TestOU1,TestOU2,TestOU3");

        testSubjectField.add(testSubjectField1);
        testSubjectField.add(testSubjectField2);
        testSubjectField.add(testSubjectField3);

        testSubject2.setSubjectFields(testSubjectField);

        assertEquals(testDistinguishedName2, testSubject2.toASN1String());

        testSubjectField.remove(testSubjectField1);
        testSubjectField.remove(testSubjectField2);
        testSubjectField.remove(testSubjectField3);

        testSubjectField1.setType(SubjectFieldType.COMMON_NAME);
        testSubjectField2.setType(SubjectFieldType.ORGANIZATION);
        testSubjectField3.setType(SubjectFieldType.ORGANIZATION_UNIT);
        testSubjectField1.setValue("TestCN1");
        testSubjectField2.setValue("TestO1\\,TestO2");
        testSubjectField3.setValue("TestOU1\\,TestOU2\\,TestOU3");

        testSubjectField.add(testSubjectField1);
        testSubjectField.add(testSubjectField2);
        testSubjectField.add(testSubjectField3);

        testSubject3.setSubjectFields(testSubjectField);

        assertEquals(testDistinguishedName3, testSubject3.toASN1String());

        assertEquals(testDistinguishedName4, testSubject.toASN1String());

        testSubjectField.remove(testSubjectField1);
        testSubjectField.remove(testSubjectField2);
        testSubjectField.remove(testSubjectField3);

        testSubjectField1.setType(SubjectFieldType.COMMON_NAME);
        testSubjectField2.setType(SubjectFieldType.ORGANIZATION);
        testSubjectField3.setType(SubjectFieldType.ORGANIZATION_UNIT);
        testSubjectField1.setValue(null);
        testSubjectField2.setValue(null);
        testSubjectField3.setValue(null);

        testSubjectField.add(testSubjectField1);
        testSubjectField.add(testSubjectField2);
        testSubjectField.add(testSubjectField3);

        testSubject4.setSubjectFields(testSubjectField);

        assertEquals(testDistinguishedName5, testSubject4.toASN1String());
    }

}
