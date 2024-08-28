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
package com.ericsson.oss.itpf.security.credmsapi.business.utils;

import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import com.ericsson.oss.itpf.security.credmsapi.api.model.SubjectAlternativeNameType;
import com.ericsson.oss.itpf.security.credmsapi.business.utils.CredentialManagerSubjectAlternateName.ALTERNATE_NAME_TYPE;

public class CredentialManagerSubjectAlternateNameImplTest {

    private CredentialManagerSubjectAlternateName subAltName;

    @Test
    public void testEmail() {
        final SubjectAlternativeNameType subAltNameType = new SubjectAlternativeNameType();

        final List<String> emailList = new ArrayList<String>();
        emailList.add("pippo.caio@ericsson.se");
        subAltNameType.setEmail(emailList);
        this.subAltName = new CredentialManagerSubjectAlternateNameImpl(subAltNameType);
    }

    @Test
    public void testRegisterId() {
        final SubjectAlternativeNameType subAltNameType = new SubjectAlternativeNameType();

        final List<String> registeredid = new ArrayList<String>();
        registeredid.add("1.2.3.4");
        subAltNameType.setRegisteredid(registeredid);
        this.subAltName = new CredentialManagerSubjectAlternateNameImpl(subAltNameType);
    }
    
    @Test
    public void testWrongandEmptyObject() {
        ALTERNATE_NAME_TYPE altName = null;
        try {
            CredentialManagerSubjectAlternateName.ALTERNATE_NAME_TYPE.valueOf("wrongValue");
            assertTrue(false);
        } catch(IllegalArgumentException e) {
            assertTrue(true);
        }
        altName = CredentialManagerSubjectAlternateName.ALTERNATE_NAME_TYPE.valueOf("DNS");
        ALTERNATE_NAME_TYPE[] values = CredentialManagerSubjectAlternateName.ALTERNATE_NAME_TYPE.values();
        assertTrue(values.length == 7);
        
        this.subAltName = null;
        this.subAltName = new CredentialManagerSubjectAlternateNameImpl(null);
        assertTrue(this.subAltName.getType() == null && this.subAltName.getValue() == null && this.subAltName.getAttribute() == null);
        this.subAltName = new CredentialManagerSubjectAlternateNameImpl("wrongObject");
        assertTrue(this.subAltName.getType() == null && this.subAltName.getValue() == null && this.subAltName.getAttribute() == null);
        final SubjectAlternativeNameType subAltNameType = new SubjectAlternativeNameType();
        this.subAltName = new CredentialManagerSubjectAlternateNameImpl(subAltNameType);
        assertTrue(this.subAltName.getAttribute() != null);
        //just covering
        this.subAltName.setValue(null);
        this.subAltName.setType(null);
        assertTrue(this.subAltName.getType() == null && this.subAltName.getValue() == null && this.subAltName.getAttribute() != null);
        //TODO attributes getValues null or empty for all types
        final List<String> dirList = new ArrayList<String>();
        dirList.add("");
        subAltNameType.setDirectoryname(dirList);
        final List<String> dnsList = new ArrayList<String>();
        dnsList.add("");
        subAltNameType.setDns(dnsList);
        final List<String> emailList = new ArrayList<String>();
        emailList.add("");
        subAltNameType.setEmail(emailList);
        final List<String> ipList = new ArrayList<String>();
        ipList.add("");
        subAltNameType.setIpaddress(ipList);
        final List<String> registeredid = new ArrayList<String>();
        registeredid.add("");
        subAltNameType.setRegisteredid(registeredid);
        final List<String> uriList = new ArrayList<String>();
        uriList.add("");
        subAltNameType.setUri(uriList);
        this.subAltName = new CredentialManagerSubjectAlternateNameImpl(subAltNameType);
        assertTrue(subAltName.getAttribute() != null);
        dirList.clear();
        dnsList.clear();
        emailList.clear();
        ipList.clear();
        registeredid.clear();
        uriList.clear();
        dirList.add(null);
        dnsList.add(null);
        emailList.add(null);
        ipList.add(null);
        registeredid.add(null);
        uriList.add(null);
        this.subAltName = new CredentialManagerSubjectAlternateNameImpl(subAltNameType);
        assertTrue(subAltName.getAttribute() != null);
    }

}
