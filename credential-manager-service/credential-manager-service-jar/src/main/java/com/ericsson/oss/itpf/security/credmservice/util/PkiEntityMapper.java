/*------------------------------------------------------------------------------
 *******************************************************************************
 * COPYRIGHT Ericsson 2012
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
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.Map.Entry;

import com.ericsson.oss.itpf.security.credmservice.exceptions.PkiEntityMapperException;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlAbstractSubjectAltNameValueType;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlEdiPartyName;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlEntity;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlOtherName;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlSubjectAltNameFieldType;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlSubjectAltNameString;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlSubjectAltNameValue;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlSubjectFieldType;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlSubjectMapModeller;
import com.ericsson.oss.itpf.security.pki.common.model.Algorithm;
import com.ericsson.oss.itpf.security.pki.common.model.EntityInfo;
import com.ericsson.oss.itpf.security.pki.common.model.Subject;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectField;
import com.ericsson.oss.itpf.security.pki.common.model.SubjectFieldType;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.EdiPartyName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.OtherName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltName;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameField;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameFieldType;
import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameString;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.Entity;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.EntityProfile;

public final class PkiEntityMapper {

    private PkiEntityMapper() {
    } //Only static methods

    public static Entity ConvertEntityFrom(final XmlEntity xmlEntity) throws PkiEntityMapperException {

        final Entity pkiEntity = new Entity();
		final EntityInfo entityInfo = new EntityInfo();
        final Algorithm pkiAlgorithm = new Algorithm();
        final Map<SubjectFieldType, String> subjectMap = new HashMap<SubjectFieldType, String>();

        if (xmlEntity == null) {
            throw new PkiEntityMapperException("Input parameter is NULL");
        }

        /**
         * set PublishCertificatetoTDPS
         */
        if (xmlEntity.isPublishCertificatetoTDPS() != null) {
            pkiEntity.setPublishCertificatetoTDPS(xmlEntity.isPublishCertificatetoTDPS());
        }

        /**
         * setEntityProfileName
         */
        if(pkiEntity.getEntityProfile() == null) {
        	final EntityProfile entityprofile = new EntityProfile();
        	pkiEntity.setEntityProfile(entityprofile);
        }
        pkiEntity.getEntityProfile().setName(xmlEntity.getEntityProfileName());

        /**
         * setoTP
         */

        if (xmlEntity.getOTP() != null) {      	
            entityInfo.setOTP(xmlEntity.getOTP());
        }

        /**
         * setKeyGenerationAlgorithm
         */

        if (xmlEntity.getKeyGenerationAlgorithm() != null) {
            pkiAlgorithm.setKeySize(xmlEntity.getKeyGenerationAlgorithm().getKeySize().intValue());
            pkiAlgorithm.setName(xmlEntity.getKeyGenerationAlgorithm().getName());
            pkiEntity.setKeyGenerationAlgorithm(pkiAlgorithm);
        }
        
        /**
         * setName
         */


        entityInfo.setName(xmlEntity.getName());

        /**
         * setSubject
         */

        Subject subject = new Subject();
        
        if (xmlEntity.getSubject() != null) {
            final List<XmlSubjectMapModeller.XmlSubjectEntry> xmlsubjectenty = xmlEntity.getSubject().getSubjectDN().getSubjectEntry();

            for (final XmlSubjectMapModeller.XmlSubjectEntry xmlsubjectentry : xmlsubjectenty) {
                subjectMap.put(convertSubjectFieldType(xmlsubjectentry.getType()), xmlsubjectentry.getValue());
            }

            final Subject pkiSubject = new Subject();
            for (Entry<SubjectFieldType, String> entrySubMap : subjectMap.entrySet()){
                final SubjectField subfieldTemp = new SubjectField();
            	subfieldTemp.setType(entrySubMap.getKey());
            	subfieldTemp.setValue(entrySubMap.getValue());
            	pkiSubject.getSubjectFields().add(subfieldTemp);
            }

            subject = pkiSubject;
        }

        entityInfo.setSubject(subject);


        /**
         * getSubjectAltNameValues
         */
        SubjectAltName subjectaltname = new SubjectAltName();
        if (xmlEntity.getSubjectAltNameValues() != null) {
        	final SubjectAltName pkisubjectAltName = new SubjectAltName();

            final List<XmlSubjectAltNameValue> xmlsubjectAltNameValue = xmlEntity.getSubjectAltNameValues().getSubjectAltNameValue();

        	final List<SubjectAltNameField> pkiSubjectAltNameFieldList = new ArrayList<SubjectAltNameField>();

            for (final XmlSubjectAltNameValue xmlsubjectaltnamevalue : xmlsubjectAltNameValue) {

            	final SubjectAltNameField subANFTemp = new SubjectAltNameField();
            	subANFTemp.setType(convertSubjectAltName(xmlsubjectaltnamevalue.getType()));

                final XmlAbstractSubjectAltNameValueType XmlAbstractAltNameType = xmlsubjectaltnamevalue.getValue();
                if (XmlAbstractAltNameType instanceof XmlSubjectAltNameString) {
                    final SubjectAltNameString y = new SubjectAltNameString();

                    if (((XmlSubjectAltNameString) XmlAbstractAltNameType).getStringValue() != null) {
                          y.setValue(((XmlSubjectAltNameString) XmlAbstractAltNameType).getStringValue());
                    }
                  	subANFTemp.setValue(y);
                }

                if (XmlAbstractAltNameType instanceof XmlOtherName) {
                   final OtherName y = new OtherName();
                   y.setTypeId(((XmlOtherName) XmlAbstractAltNameType).getTypeId());
                   y.setValue(((XmlOtherName) XmlAbstractAltNameType).getValue());
                   subANFTemp.setValue(y);
                }

               if (XmlAbstractAltNameType instanceof XmlEdiPartyName) {
                  final EdiPartyName y = new EdiPartyName();
                  y.setNameAssigner(((XmlEdiPartyName) XmlAbstractAltNameType).getNameAssigner());
                  y.setPartyName(((XmlEdiPartyName) XmlAbstractAltNameType).getPartyName());
                  subANFTemp.setValue(y);
                }
             	pkiSubjectAltNameFieldList.add(subANFTemp);
                	
            }
            pkisubjectAltName.setSubjectAltNameFields(pkiSubjectAltNameFieldList);
            subjectaltname = pkisubjectAltName;
        }
        entityInfo.setSubjectAltName(subjectaltname);
        pkiEntity.setEntityInfo(entityInfo);

        return pkiEntity;
    }

    private static SubjectFieldType convertSubjectFieldType(final XmlSubjectFieldType xmlType) throws PkiEntityMapperException {

        switch (xmlType) {
            case COMMON_NAME:
                return SubjectFieldType.COMMON_NAME;
            case SURNAME:
                return SubjectFieldType.SURNAME;
            case COUNTRY_NAME:
                return SubjectFieldType.COUNTRY_NAME;
            case LOCALITY_NAME:
                return SubjectFieldType.LOCALITY_NAME;
            case STATE:
                return SubjectFieldType.STATE;
            case STREET_ADDRESS:
                return SubjectFieldType.STREET_ADDRESS;
            case ORGANIZATION:
                return SubjectFieldType.ORGANIZATION;
            case ORGANIZATION_UNIT:
                return SubjectFieldType.ORGANIZATION_UNIT;
            case DN_QUALIFIER:
                return SubjectFieldType.DN_QUALIFIER;
            case TITLE:
                return SubjectFieldType.TITLE;
            case GIVEN_NAME:
                return SubjectFieldType.GIVEN_NAME;
            case SERIAL_NUMBER:
                return SubjectFieldType.SERIAL_NUMBER;
            default:
                throw new PkiEntityMapperException("Unexpected XmlSubjectFieldType value to convert");
        }

    }

    private static SubjectAltNameFieldType convertSubjectAltName(final XmlSubjectAltNameFieldType xmlType) throws PkiEntityMapperException {

        switch (xmlType) {
            case RFC_822_NAME:
                return SubjectAltNameFieldType.RFC822_NAME;
            case OTHER_NAME:
                return SubjectAltNameFieldType.OTHER_NAME;
            case EDI_PARTY_NAME:
                return SubjectAltNameFieldType.EDI_PARTY_NAME;
            case DNS_NAME:
                return SubjectAltNameFieldType.DNS_NAME;
//            case X_400_ADDRESS:
//                return SubjectAltNameFieldType.X400_ADDRESS;
            case DIRECTORY_NAME:
                return SubjectAltNameFieldType.DIRECTORY_NAME;
            case UNIFORM_RESOURCE_IDENTIFIER:
                return SubjectAltNameFieldType.UNIFORM_RESOURCE_IDENTIFIER;
            case IP_ADDRESS:
                return SubjectAltNameFieldType.IP_ADDRESS;
            case REGESTERED_ID:
                return SubjectAltNameFieldType.REGESTERED_ID;
            default:
                throw new PkiEntityMapperException("Unexpected XmlSubjectAltNameFieldType value to convert");
        }
    }

}
