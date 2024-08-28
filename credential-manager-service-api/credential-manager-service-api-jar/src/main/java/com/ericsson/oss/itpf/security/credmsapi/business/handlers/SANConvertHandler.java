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
package com.ericsson.oss.itpf.security.credmsapi.business.handlers;

import java.util.ArrayList;
import java.util.List;

import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.api.exceptions.IssueCertificateException;
import com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.ErrorMsg;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerOtherName;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerSubjectAltName;

public class SANConvertHandler {

    private static final Logger LOG = LogManager.getLogger(SANConvertHandler.class);
	
    public CredentialManagerSubjectAltName xmlToService(final SubjectAlternativeNameType subjectAltNameFromXml) {
        /**
         * Convert SubjectAlternativeNameType to CredentialManagerSubjectAltName
         */

        final CredentialManagerSubjectAltName subjectAltNameFromProfile = new CredentialManagerSubjectAltName();

        /*
         * To DO: The TypeId in the CredentialManagerOtherName from XML doesn't exist --- now is empty String
         */
        // List<CredentialManagerOtherName> othername = new
        // ArrayList<CredentialManagerOtherName>();
        // CredentialManagerOtherName element = new
        // CredentialManagerOtherName();
        // element.setValue("othername");
        // element.setTypeId("");
        // othername.add(element);
        // subjectDefaultAlternativeName.setOtherName(othername);

        final List<String> listOthername = subjectAltNameFromXml.getOthername();
        final List<CredentialManagerOtherName> names = new ArrayList<CredentialManagerOtherName>();
        for (final String name : listOthername) {
            final CredentialManagerOtherName element = new CredentialManagerOtherName();
            element.setValue(name);
            element.setTypeId("");
            names.add(element);
        }

        subjectAltNameFromProfile.setDirectoryName(subjectAltNameFromXml.getDirectoryname());
        subjectAltNameFromProfile.setDNSName(subjectAltNameFromXml.getDns());
        subjectAltNameFromProfile.setX400Address(subjectAltNameFromXml.getEmail());
        subjectAltNameFromProfile.setUniformResourceIdentifier(subjectAltNameFromXml.getUri());
        subjectAltNameFromProfile.setIPAddress(subjectAltNameFromXml.getIpaddress());
        subjectAltNameFromProfile.setOtherName(names);
        subjectAltNameFromProfile.setRegisteredID(subjectAltNameFromXml.getRegisteredid());

        return subjectAltNameFromProfile;
    }

    public SubjectAlternativeNameType serviceToXml(final CredentialManagerSubjectAltName subjectAltNameFromService) {

        final SubjectAlternativeNameType subjectAltNameFromXml = new SubjectAlternativeNameType();

        final List<CredentialManagerOtherName> names = subjectAltNameFromService.getOtherName();
        final List<String> listOthername = new ArrayList<String>();
        for (final CredentialManagerOtherName name : names) {
            listOthername.add(name.getValue());
        }

        subjectAltNameFromXml.setDirectoryname(subjectAltNameFromService.getDirectoryName());
        subjectAltNameFromXml.setDns(subjectAltNameFromService.getDNSName());
        subjectAltNameFromXml.setEmail(subjectAltNameFromService.getX400Address());
        subjectAltNameFromXml.setUri(subjectAltNameFromService.getUniformResourceIdentifier());
        subjectAltNameFromXml.setIpaddress(subjectAltNameFromService.getIPAddress());
        subjectAltNameFromXml.setOthername(listOthername);
        subjectAltNameFromXml.setRegisteredid(subjectAltNameFromService.getRegisteredID());

        return subjectAltNameFromXml;

    }

    public CredentialManagerSubjectAltName setSubjectAltName(final SubjectAlternativeNameType subjectAltName, final CredentialManagerProfileInfo profileInfo) throws IssueCertificateException {
        CredentialManagerSubjectAltName cmSubjectAltName = null;
        if(profileInfo == null) {
            LOG.error(ErrorMsg.API_ERROR_HANDLERS_CHECK_PROFILEINFO);
            throw new IssueCertificateException("SANconvertHandler  exception profileInfo == null");
        }
        if (subjectAltName != null) {
            /**
             * Convert SubjectAlternativeNameType subjectAltName to CredentialManagerSubjecAltName
             * and merge it with possible values from profile
             */            
            cmSubjectAltName = this.mergeSAN(profileInfo.getSubjectDefaultAlternativeName() ,this.xmlToService(subjectAltName));
        } else {
            cmSubjectAltName = profileInfo.getSubjectDefaultAlternativeName();
        }
        return cmSubjectAltName;
    }

    public CredentialManagerSubjectAltName mergeSAN(final CredentialManagerSubjectAltName sanProf, final CredentialManagerSubjectAltName sanXml) {
        
        if(sanProf == null) {
            return sanXml;
        }
        
        if(sanXml.getDirectoryName().isEmpty() && !sanProf.getDirectoryName().isEmpty()) {
            sanXml.setDirectoryName(sanProf.getDirectoryName());
        }
        if(sanXml.getDNSName().isEmpty() && !sanProf.getDNSName().isEmpty()) {
            sanXml.setDNSName(sanProf.getDNSName());
        }
        if(sanXml.getEdiPartyName().isEmpty() && !sanProf.getEdiPartyName().isEmpty()) {
            sanXml.setEdiPartyName(sanProf.getEdiPartyName());
        }
        if(sanXml.getIPAddress().isEmpty() && !sanProf.getIPAddress().isEmpty()) {
            sanXml.setIPAddress(sanProf.getIPAddress());
        }
        if(sanXml.getOtherName().isEmpty() && !sanProf.getOtherName().isEmpty()) {
            sanXml.setOtherName(sanProf.getOtherName());
        }
        if(sanXml.getRegisteredID().isEmpty() && !sanProf.getRegisteredID().isEmpty()) {
            sanXml.setRegisteredID(sanProf.getRegisteredID());
        }
        if(sanXml.getRfc822Name().isEmpty() && !sanProf.getRfc822Name().isEmpty()) {
            sanXml.setRfc822Name(sanProf.getRfc822Name());
        }
        if(sanXml.getUniformResourceIdentifier().isEmpty() && !sanProf.getUniformResourceIdentifier().isEmpty()) {
            sanXml.setUniformResourceIdentifier(sanProf.getUniformResourceIdentifier());
        }
        if(sanXml.getX400Address().isEmpty() && !sanProf.getX400Address().isEmpty()) {
            sanXml.setX400Address(sanProf.getX400Address());
        }
        
        return sanXml;
        
    }
    
    /**
     * isSubjectAltNameEmpty
     * 
     * @param subjectAltName
     * @return
     */
    public boolean isSubjectAltNameEmpty(final SubjectAlternativeNameType subjectAltName) {

        if (subjectAltName == null) {
            return true;
        }

        if (!subjectAltName.getDirectoryname().isEmpty()) {
            return false;
        }

        if (!subjectAltName.getDns().isEmpty()) {
            return false;
        }

        if (!subjectAltName.getEmail().isEmpty()) {
            return false;
        }

        if (!subjectAltName.getIpaddress().isEmpty()) {
            return false;
        }

        if (!subjectAltName.getRegisteredid().isEmpty()) {
            return false;
        }

        if (!subjectAltName.getUri().isEmpty()) {
            return false;
        }

        if (!subjectAltName.getOthername().isEmpty()) {
            return false;
        }
        return true;
    }

}
