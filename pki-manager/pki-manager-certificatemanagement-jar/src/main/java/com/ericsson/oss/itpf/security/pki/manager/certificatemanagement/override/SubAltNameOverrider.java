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
package com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.override;

import java.util.*;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.*;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.request.CertificateRequest;
import com.ericsson.oss.itpf.security.pki.manager.certificatemanagement.util.CertificateRequestParser;
import com.ericsson.oss.itpf.security.pki.manager.common.codes.Constants;

/**
 * Class for handling overriding scenarios.
 * 
 * <p>
 * Overriding scenarios applicable for Subject and SubjectAltName fields.
 * </p>
 * 
 */

// TODO Improve the handling of validations and overriding Scenarios, this will be addressed as part of TORF-59437
// TODO Refactor CRMF design, this comment will be addressed as part of TORF-70743
public class SubAltNameOverrider {

    /**
     * Method for overriding entity subjectAltName fields values with CertificateRequest subjectAltName fields values. If entity subjectAltName field value has place holder then replace
     * CertificateRequest subjectAltName field value.
     * 
     * @param entitySubjetAltName
     *            The entity subjectAltName values.
     * @param certificateRequest
     *            The CertificateRequest Object.
     * @return the subjectAltName containing the overridden values.
     */

    public SubjectAltName overrideSubjectAltName(final SubjectAltName entitySubjetAltName, final CertificateRequest certificateRequest) {

        final SubjectAltName csrSubjectAltName = CertificateRequestParser.extractSubjectAltName(certificateRequest);

        final List<SubjectAltNameField> csrSubjectAltNameFields = csrSubjectAltName.getSubjectAltNameFields();
        final List<SubjectAltNameField> entitySubjectAltNameFields = entitySubjetAltName.getSubjectAltNameFields();

        overrideSubjectAltName(entitySubjectAltNameFields, csrSubjectAltNameFields);
        return entitySubjetAltName;

    }

    private void overrideSubjectAltName(final List<SubjectAltNameField> entitySubjectAltNameFields, final List<SubjectAltNameField> csrSubjectAltNameFields) {

        List<AbstractSubjectAltNameFieldValue> ediPartyNameList = null;
        List<AbstractSubjectAltNameFieldValue> otherNameList = null;
        List<AbstractSubjectAltNameFieldValue> dnsNameList = null;
        List<AbstractSubjectAltNameFieldValue> directory_NameList = null;
        List<AbstractSubjectAltNameFieldValue> uniform_Resource_IdentitfierList = null;
        List<AbstractSubjectAltNameFieldValue> ip_AddressList = null;
        List<AbstractSubjectAltNameFieldValue> rfc822_NameList = null;
        List<AbstractSubjectAltNameFieldValue> regesteredIdList = null;

        for (final SubjectAltNameField entitySubjectAltNameField : entitySubjectAltNameFields) {

            switch (entitySubjectAltNameField.getType()) {
            case EDI_PARTY_NAME:
                ediPartyNameList = overrideEdiPartyName(entitySubjectAltNameFields, csrSubjectAltNameFields, entitySubjectAltNameField);
                break;
            case OTHER_NAME:
                otherNameList = overrideOtherName(entitySubjectAltNameFields, csrSubjectAltNameFields, entitySubjectAltNameField);
                break;
            case DNS_NAME:
                dnsNameList = overrideOtherFields(entitySubjectAltNameFields, csrSubjectAltNameFields, entitySubjectAltNameField, dnsNameList);
                break;
            case DIRECTORY_NAME:
                directory_NameList = overrideOtherFields(entitySubjectAltNameFields, csrSubjectAltNameFields, entitySubjectAltNameField, directory_NameList);
                break;
            case UNIFORM_RESOURCE_IDENTIFIER:
                uniform_Resource_IdentitfierList = overrideOtherFields(entitySubjectAltNameFields, csrSubjectAltNameFields, entitySubjectAltNameField, uniform_Resource_IdentitfierList);
                break;
            case IP_ADDRESS:
                ip_AddressList = overrideOtherFields(entitySubjectAltNameFields, csrSubjectAltNameFields, entitySubjectAltNameField, ip_AddressList);
                break;
            case RFC822_NAME:
                rfc822_NameList = overrideOtherFields(entitySubjectAltNameFields, csrSubjectAltNameFields, entitySubjectAltNameField, rfc822_NameList);
                break;
            default:
                regesteredIdList = overrideOtherFields(entitySubjectAltNameFields, csrSubjectAltNameFields, entitySubjectAltNameField, regesteredIdList);

            }

        }

        addAndRemoveSubjectAltNameFields(entitySubjectAltNameFields, ediPartyNameList, SubjectAltNameFieldType.EDI_PARTY_NAME);
        addAndRemoveSubjectAltNameFields(entitySubjectAltNameFields, otherNameList, SubjectAltNameFieldType.OTHER_NAME);
        addAndRemoveSubjectAltNameFields(entitySubjectAltNameFields, dnsNameList, SubjectAltNameFieldType.DNS_NAME);
        addAndRemoveSubjectAltNameFields(entitySubjectAltNameFields, directory_NameList, SubjectAltNameFieldType.DIRECTORY_NAME);
        addAndRemoveSubjectAltNameFields(entitySubjectAltNameFields, uniform_Resource_IdentitfierList, SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER);
        addAndRemoveSubjectAltNameFields(entitySubjectAltNameFields, ip_AddressList, SubjectAltNameFieldType.IP_ADDRESS);
        addAndRemoveSubjectAltNameFields(entitySubjectAltNameFields, rfc822_NameList, SubjectAltNameFieldType.RFC822_NAME);
        addAndRemoveSubjectAltNameFields(entitySubjectAltNameFields, regesteredIdList, SubjectAltNameFieldType.REGESTERED_ID);
    }

    private List<AbstractSubjectAltNameFieldValue> overrideEdiPartyName(final List<SubjectAltNameField> entitySubjectAltNameFields, final List<SubjectAltNameField> csrSubjectAltNameFields,
            final SubjectAltNameField entitySubjectAltNameField) {

        List<AbstractSubjectAltNameFieldValue> entityEdiPartyNameList = new ArrayList<AbstractSubjectAltNameFieldValue>();
        List<AbstractSubjectAltNameFieldValue> csrEdiPartyNameList;

        final EdiPartyName ediPartyName = (EdiPartyName) entitySubjectAltNameField.getValue();

        if (ediPartyName.getNameAssigner().equals(Constants.OVERRIDE_OPERATOR) && ediPartyName.getPartyName().equals(Constants.OVERRIDE_OPERATOR)) {

            final EdiPartyName removableEdiPartyName = new EdiPartyName();
            removableEdiPartyName.setNameAssigner("?");
            removableEdiPartyName.setPartyName("?");

            entityEdiPartyNameList = groupSubjectAltNameFields(entitySubjectAltNameFields, entitySubjectAltNameField.getType());
            csrEdiPartyNameList = groupSubjectAltNameFields(csrSubjectAltNameFields, entitySubjectAltNameField.getType());

            substituteSubjectAltNameFields(entityEdiPartyNameList, csrEdiPartyNameList, removableEdiPartyName);
        }
        return entityEdiPartyNameList;
    }

    private List<AbstractSubjectAltNameFieldValue> overrideOtherName(final List<SubjectAltNameField> entitySubjectAltNameFields, final List<SubjectAltNameField> csrSubjectAltNameFields,
            final SubjectAltNameField entitySubjectAltNameField) {

        List<AbstractSubjectAltNameFieldValue> entityOtherNameList = new ArrayList<AbstractSubjectAltNameFieldValue>();
        List<AbstractSubjectAltNameFieldValue> csrOtherNameList;

        final OtherName othername = (OtherName) entitySubjectAltNameField.getValue();
        if (othername.getTypeId().equals(Constants.OVERRIDE_OPERATOR) && othername.getValue().equals(Constants.OVERRIDE_OPERATOR)) {

            final OtherName removableOtherName = new OtherName();
            removableOtherName.setTypeId("?");
            removableOtherName.setValue("?");

            entityOtherNameList = groupSubjectAltNameFields(entitySubjectAltNameFields, entitySubjectAltNameField.getType());
            csrOtherNameList = groupSubjectAltNameFields(csrSubjectAltNameFields, entitySubjectAltNameField.getType());

            substituteSubjectAltNameFields(entityOtherNameList, csrOtherNameList, removableOtherName);
        }
        return entityOtherNameList;
    }

    private List<AbstractSubjectAltNameFieldValue> overrideOtherFields(final List<SubjectAltNameField> entitySubjectAltNameFields, final List<SubjectAltNameField> csrSubjectAltNameFields,
            final SubjectAltNameField entitySubjectAltNameField, List<AbstractSubjectAltNameFieldValue> entityFieldValueList) {

        List<AbstractSubjectAltNameFieldValue> csrFiledValueList = null;

        final SubjectAltNameString subjectAltNameString = (SubjectAltNameString) entitySubjectAltNameField.getValue();
        if (subjectAltNameString.getValue().equals(Constants.OVERRIDE_OPERATOR)) {

            final SubjectAltNameString subjectNameString = new SubjectAltNameString();
            subjectNameString.setValue("?");

            entityFieldValueList = groupSubjectAltNameFields(entitySubjectAltNameFields, entitySubjectAltNameField.getType());
            csrFiledValueList = groupSubjectAltNameFields(csrSubjectAltNameFields, entitySubjectAltNameField.getType());

            substituteSubjectAltNameFields(entityFieldValueList, csrFiledValueList, subjectNameString);

        }
        return entityFieldValueList;
    }

    private List<AbstractSubjectAltNameFieldValue> groupSubjectAltNameFields(final List<SubjectAltNameField> entitySubjectAltNameFields, final SubjectAltNameFieldType subjectAltNameFieldType) {

        final List<AbstractSubjectAltNameFieldValue> subjectAltNameList = new ArrayList<AbstractSubjectAltNameFieldValue>();
        for (final Iterator<SubjectAltNameField> iterator = entitySubjectAltNameFields.iterator(); iterator.hasNext();) {

            final SubjectAltNameField entitySubjectAltNameField = iterator.next();

            if ((entitySubjectAltNameField.getType() == subjectAltNameFieldType)) {

                if (entitySubjectAltNameField.getValue() instanceof SubjectAltNameString) {
                    final SubjectAltNameString subjectAltNameString = (SubjectAltNameString) entitySubjectAltNameField.getValue();
                    subjectAltNameList.add(subjectAltNameString);
                } else if (entitySubjectAltNameField.getValue() instanceof EdiPartyName) {
                    final EdiPartyName ediPartyName = (EdiPartyName) entitySubjectAltNameField.getValue();
                    subjectAltNameList.add(ediPartyName);
                } else {
                    final OtherName otherName = (OtherName) entitySubjectAltNameField.getValue();
                    subjectAltNameList.add(otherName);
                }
            }

        }
        return subjectAltNameList;

    }

    private <T extends AbstractSubjectAltNameFieldValue> void addAndRemoveSubjectAltNameFields(final List<SubjectAltNameField> entitySubjectAltNameFields, final List<T> entityFieldList,
            final SubjectAltNameFieldType entitySubjectAltNameFieldType) {

        if (entityFieldList != null) {

            for (final Iterator<SubjectAltNameField> iterator = entitySubjectAltNameFields.iterator(); iterator.hasNext();) {

                final SubjectAltNameField subjectAltNameField = iterator.next();
                if (subjectAltNameField.getType() == entitySubjectAltNameFieldType) {
                    iterator.remove();
                }

            }

            addSubjectAltNameFileds(entitySubjectAltNameFields, entityFieldList, entitySubjectAltNameFieldType);

        }

    }

    private <T extends AbstractSubjectAltNameFieldValue> void addSubjectAltNameFileds(final List<SubjectAltNameField> entitySubjectAltNameFields, final List<T> entityFieldList,
            final SubjectAltNameFieldType entitySubjectAltNameFieldType) {
        for (final T entityField : entityFieldList) {

            final SubjectAltNameField subjectAltNameField = new SubjectAltNameField();
            subjectAltNameField.setType(entitySubjectAltNameFieldType);

            if (entityField instanceof SubjectAltNameString) {
                subjectAltNameField.setValue((SubjectAltNameString) entityField);
            } else if (entityField instanceof EdiPartyName) {
                final EdiPartyName ediPartyName = (EdiPartyName) entityField;
                subjectAltNameField.setValue(ediPartyName);
            } else {
                final OtherName otherName = (OtherName) entityField;
                subjectAltNameField.setValue(otherName);
            }

            entitySubjectAltNameFields.add(subjectAltNameField);
        }
    }

    private <T extends Object> List<T> substituteSubjectAltNameFields(final List<T> endEntitySubjectAltNameFieldList, final List<T> csrSubjectAltNameFieldList, final T removable) {
        int count = 0;
        if (!endEntitySubjectAltNameFieldList.isEmpty()) {
            while (endEntitySubjectAltNameFieldList.remove(removable)) {
                count++;
            }
            if (count > 0) {
                if (csrSubjectAltNameFieldList != null && !csrSubjectAltNameFieldList.isEmpty()) {
                    csrSubjectAltNameFieldList.removeAll(endEntitySubjectAltNameFieldList);
                    if (csrSubjectAltNameFieldList.size() <= count) {
                        endEntitySubjectAltNameFieldList.addAll(csrSubjectAltNameFieldList);
                    } else {
                        endEntitySubjectAltNameFieldList.addAll(csrSubjectAltNameFieldList.subList(0, count));
                    }
                }
            }
        }
        return endEntitySubjectAltNameFieldList;
    }

}
