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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.common.data;

import java.util.ArrayList;
import java.util.List;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.asn1.x509.GeneralName;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificaterequest.CertificateRequestGenerationException;

public class SubjectAltNameSetUPData {
	
	private static final String IP_ADDRESS_VALUE = "1234::2001:cdba";

    /**
     * Method to generate SubjectAltNameString using value.
     * 
     * @param dir
     *            value to generate SubjectAltNameString.
     * @return generated key pair.
     */
    public SubjectAltNameString getSubjectAltNameString(final String dir) {

        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue(dir);
        return subjectAltNameString;
    }

    /**
     * Method to generate SubjectAltName.
     * 
     * @return SubjectAltNameValues.
     */
    public SubjectAltName getSubjectAltName() {

        final SubjectAltName subjectAltName = new SubjectAltName();
        final List<SubjectAltNameField> subjectAltNameFieldList = new ArrayList<SubjectAltNameField>();
        subjectAltName.setSubjectAltNameFields(subjectAltNameFieldList);
        return subjectAltName;
    }

    /**
     * Method to generate SubjectAltName using SubjectAltNameFieldType and list of string values.
     * 
     * @param dir
     *            list of values to generate SubjectAltNameValues.
     * @param subjectAltNameFieldType
     *            enum field to generate SubjectAltNameValues
     * @return SubjectAltNameValues.
     */
    public SubjectAltName getSubjectAltName(final SubjectAltNameFieldType subjectAltNameFieldType, final String... dir) {

        final SubjectAltName subjectAltName = new SubjectAltName();
        final List<SubjectAltNameField> subjectAltNameFieldList = new ArrayList<SubjectAltNameField>();

        for (int i = 0; i < dir.length; i++) {

            final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
            subjectAltNameField.setType(subjectAltNameFieldType);
            final SubjectAltNameString subjectAltNameString = getSubjectAltNameString(dir[i]);
            subjectAltNameField.setValue(subjectAltNameString);
            subjectAltNameFieldList.add(subjectAltNameField);
        }

        subjectAltName.setSubjectAltNameFields(subjectAltNameFieldList);
        return subjectAltName;
    }

    /**
     * Method to generate SubjectAltNameValues using SubjectAltNameFieldType and list of AbstractSubjectAltNameValueType.
     * 
     * @param subjectAltNameList
     *            list of values to generate SubjectAltNameValues.
     * @param subjectAltNameFieldType
     *            enum field to generate SubjectAltNameValues
     * @return SubjectAltNameValues.
     */
    public SubjectAltName getSubjectAltName(final SubjectAltNameFieldType subjectAltNameFieldType, final AbstractSubjectAltNameFieldValue... subjectAltNameFieldValueList) {

        final SubjectAltName subjectAltName = new SubjectAltName();
        final List<SubjectAltNameField> subjectAltNameFieldList = new ArrayList<SubjectAltNameField>();
        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();

        for (final AbstractSubjectAltNameFieldValue subjectAltNameFieldValue : subjectAltNameFieldValueList) {
            if (subjectAltNameFieldType == SubjectAltNameFieldType.EDI_PARTY_NAME) {
                subjectAltNameField.setType(SubjectAltNameFieldType.EDI_PARTY_NAME);
                subjectAltNameField.setValue(subjectAltNameFieldValue);
                subjectAltNameFieldList.add(subjectAltNameField);
            } else {
                subjectAltNameField.setType(SubjectAltNameFieldType.OTHER_NAME);
                subjectAltNameField.setValue(subjectAltNameFieldValue);
                subjectAltNameFieldList.add(subjectAltNameField);
            }
        }

        subjectAltName.setSubjectAltNameFields(subjectAltNameFieldList);
        return subjectAltName;
    }
    
    private static AbstractSubjectAltNameFieldValue getSubjectAltNameIpAddressString(final String value) {
        final SubjectAltNameString subjectAltNameString = new SubjectAltNameString();
        subjectAltNameString.setValue(value);

        return subjectAltNameString;
    }
    
    public SubjectAltName getSANForEntity() {
        final SubjectAltName subjectAltname = new SubjectAltName();
        final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
        final List<SubjectAltNameField> subjectAltNameFields = new ArrayList<SubjectAltNameField>();

        subjectAltNameField.setType(SubjectAltNameFieldType.IP_ADDRESS);
        subjectAltNameField.setValue(getSubjectAltNameIpAddressString(IP_ADDRESS_VALUE));
        subjectAltNameFields.add(subjectAltNameField);

        subjectAltname.setSubjectAltNameFields(subjectAltNameFields);
        
        return subjectAltname;
    }

    /**
     * Method to generate list of GeneralName objects by passing list of SubjectAltName values .
     * 
     * @param subjectAltNameList
     *            list of values to generate GeneralName list.
     * 
     * @return List of GeneralName .
     */
    public List<GeneralName> getGeneralNameList(final List<SubjectAltNameField> subjectAltNameFieldList) {

        final List<GeneralName> generalNameList = new ArrayList<GeneralName>();

        for (final SubjectAltNameField subjectAltNameField : subjectAltNameFieldList) {
            getProviderSANFieldType(generalNameList, subjectAltNameField);
        }

        return generalNameList;
    }

    /**
     * Method to generate list of GeneralName objects by passing SubjectAltNameField and list of GeneralName.
     * 
     * @param type
     *            Based on the SubjectAltNameFieldType switch case will be executed.
     * @param generalNameList
     *            adds the value of GeneralName and SubjectAltNameFieldType
     * @param subjectAltNameValue
     *            subjectAltNameValue to represent the type of AbstractSubjectAltNameValueType.
     * @return List of GeneralName .
     */
    public static void getProviderSANFieldType(final List<GeneralName> generalNameList, final SubjectAltNameField subjectAltNameField) {

        final SubjectAltNameFieldType type = subjectAltNameField.getType();

        switch (type) {

        case RFC822_NAME:
            final String rfc822_name = ((SubjectAltNameString) subjectAltNameField.getValue()).getValue();
            generalNameList.add(new GeneralName(GeneralName.rfc822Name, new DERIA5String(rfc822_name)));
            break;
        case DNS_NAME:
            final String dns_name = ((SubjectAltNameString) subjectAltNameField.getValue()).getValue();
            generalNameList.add(new GeneralName(GeneralName.dNSName, new DERIA5String(dns_name)));
            break;
        case DIRECTORY_NAME:
            final String directory_name = ((SubjectAltNameString) subjectAltNameField.getValue()).getValue();
            generalNameList.add(new GeneralName(GeneralName.directoryName, new X500Name(directory_name)));
            break;
        case IP_ADDRESS:
            final String ip_address = ((SubjectAltNameString) subjectAltNameField.getValue()).getValue();
            generalNameList.add(new GeneralName(GeneralName.iPAddress, new DEROctetString(ip_address.getBytes())));
            break;
        case REGESTERED_ID:
            final String regestered_id = ((SubjectAltNameString) subjectAltNameField.getValue()).getValue();
            generalNameList.add(new GeneralName(GeneralName.registeredID, new ASN1ObjectIdentifier(regestered_id)));
            break;
        case UNIFORM_RESOURCE_IDENTIFIER:
            final String uniform_resource_identifier = ((SubjectAltNameString) subjectAltNameField.getValue()).getValue();
            generalNameList.add(new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(uniform_resource_identifier)));
            break;
        case EDI_PARTY_NAME:
            final ASN1EncodableVector v = new ASN1EncodableVector();
            final EdiPartyName ediPartyName = (EdiPartyName) subjectAltNameField.getValue();
            v.add(new DERTaggedObject(true, 0, new DERUTF8String(ediPartyName.getPartyName())));
            generalNameList.add(new GeneralName(GeneralName.ediPartyName, new DERTaggedObject(GeneralName.ediPartyName, new DERSequence(v))));
            break;
        case OTHER_NAME:
            final OtherName othername = (OtherName) subjectAltNameField.getValue();
            generalNameList.add(new GeneralName(GeneralName.otherName, ASN1Sequence.getInstance(othername.getValue())));
            break;
        default:
            throw new CertificateRequestGenerationException("Invalid type");
        }
    }
}
