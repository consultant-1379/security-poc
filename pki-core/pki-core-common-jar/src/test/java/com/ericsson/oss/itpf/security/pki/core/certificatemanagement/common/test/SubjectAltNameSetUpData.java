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
package com.ericsson.oss.itpf.security.pki.core.certificatemanagement.common.test;

import java.util.ArrayList;
import java.util.List;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;

public class SubjectAltNameSetUpData {

    private static final String SUBJECT_ALT_NAME_STRING_1 = "www.ericsson.com";
    private static final String OTHER_NAME_VALUE = "Other_arquillian";
    private static final String TYPE_ID = "12.600.12";
    private static final String EDI_PARTY_NAME = "ediPartyNameSample";
    private static final String EDI_PARTY_VALUE = "ediPartyValue";

    /**
     * Method that returns valid SubjectAltNamevalues object
     * 
     * @return SubjectAltName
     */
    public SubjectAltName getSANForCreate() {

        final SubjectAltName subjectAltName = new SubjectAltName();
        final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();

        final SubjectAltNameField dns_name = new SubjectAltNameField();

        final SubjectAltNameString dns_name_value = new SubjectAltNameString();
        dns_name_value.setValue(SUBJECT_ALT_NAME_STRING_1);

        dns_name.setType(SubjectAltNameFieldType.DNS_NAME);
        dns_name.setValue(dns_name_value);

        subjectAltNameFields.add(dns_name);

        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);

        return subjectAltName;
    }

    /**
     * Method that returns valid SubjectAltNamevalues object
     * 
     * @return SubjectAltName
     */
    public SubjectAltName getSANForCreateNotEqual() {

        final SubjectAltName subjectAltName = new SubjectAltName();
        final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();

        final SubjectAltNameField other_name = new SubjectAltNameField();
        final SubjectAltNameField edi_party_name = new SubjectAltNameField();

        final EdiPartyName editPartyNanme = new EdiPartyName();
        editPartyNanme.setNameAssigner(EDI_PARTY_NAME);
        editPartyNanme.setPartyName(EDI_PARTY_VALUE);

        edi_party_name.setType(SubjectAltNameFieldType.EDI_PARTY_NAME);
        edi_party_name.setValue(editPartyNanme);

        final OtherName otherName = new OtherName();
        otherName.setTypeId(TYPE_ID);
        otherName.setValue(OTHER_NAME_VALUE);

        other_name.setType(SubjectAltNameFieldType.OTHER_NAME);
        other_name.setValue(otherName);

        subjectAltNameFields.add(other_name);
        subjectAltNameFields.add(edi_party_name);

        subjectAltName.setSubjectAltNameFields(subjectAltNameFields);

        return subjectAltName;
    }
}
