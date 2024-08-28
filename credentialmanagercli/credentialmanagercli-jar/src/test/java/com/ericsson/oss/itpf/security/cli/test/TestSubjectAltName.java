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
package com.ericsson.oss.itpf.security.cli.test;

import static org.junit.Assert.*;

import java.io.IOException;
import java.util.ArrayList;
import java.util.List;

import javax.naming.NamingException;

import org.apache.commons.cli.ParseException;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.junit.runners.JUnit4;

import com.ericsson.oss.itpf.security.credentialmanager.cli.model.*;
import com.ericsson.oss.itpf.security.credentialmanager.cli.model.xmlbeans.*;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.*;
import com.ericsson.oss.itpf.security.credentialmanager.cli.service.api.CredentialManagerSubjectAltName.ALTERNATE_NAME_TYPE;


@RunWith(JUnit4.class)
public class TestSubjectAltName {

	final String dir = "C=AU, ST=Victoria";
	final String dns = "CN=dns";
	final String email = "em";
	final String ip = "1.2.3.4";
	final String reg = "1.2.150.1";
	final String uri = "uri";
	//final String other = "other";
	
	
    @Test
    public void testCredentialManagerSubjectAltName() throws NamingException, ParseException, IOException {
    	
    	SubjectAlternativeNameType subj = new SubjectAlternativeNameType();
    	subj.getDirectoryname().add(dir);   	
    	CredentialManagerSubjectAltName subjectAltName;
    	subjectAltName = new CredentialManagerSubjectAlternateNameImpl(subj); 	
    	assertTrue("SubjectAlternativeNameType dir ", 
    			subjectAltName.getValue().get(0).get(0).equals(dir) );
    	
    	subj = new SubjectAlternativeNameType();
    	subj.getDns().add(dns);
      	subjectAltName = new CredentialManagerSubjectAlternateNameImpl(subj); 	
    	assertTrue("SubjectAlternativeNameType dns ", 
    			subjectAltName.getValue().get(0).get(0).equals(dns) );
    	
    	subj = new SubjectAlternativeNameType();
    	subj.getEmail().add(email);
      	subjectAltName = new CredentialManagerSubjectAlternateNameImpl(subj); 	
    	assertTrue("SubjectAlternativeNameType email ", 
    			subjectAltName.getValue().get(0).get(0).equals(email) );
    	
    	subj = new SubjectAlternativeNameType();
    	subj.getIpaddress().add(ip);
      	subjectAltName = new CredentialManagerSubjectAlternateNameImpl(subj); 	
    	assertTrue("SubjectAlternativeNameType ip ", 
    			subjectAltName.getValue().get(0).get(0).equals(ip) );
    	
    	subj = new SubjectAlternativeNameType();
    	subj.getRegisteredid().add(reg);
      	subjectAltName = new CredentialManagerSubjectAlternateNameImpl(subj); 	
    	assertTrue("SubjectAlternativeNameType reg ", 
    			subjectAltName.getValue().get(0).get(0).equals(reg) );
    	
    	subj = new SubjectAlternativeNameType();
    	subj.getUri().add(uri);
      	subjectAltName = new CredentialManagerSubjectAlternateNameImpl(subj); 	
    	assertTrue("SubjectAlternativeNameType uri ", 
    			subjectAltName.getValue().get(0).get(0).equals(uri) );
    	/*
    	subj = new SubjectAlternativeNameType();
    	subj.getOthername().add(other);
    	subjectAltName = new CredentialManagerSubjectAlternateNameImpl(subj);   
    	assertTrue("SubjectAlternativeNameType other ", 
    	        subjectAltName.getValue().get(0).get(0).equals(other) );
    	 */
    	
    	assertTrue(subjectAltName.getSubjectAlternativeName() != null);
    }
    
    //Test for multiple subjectAltName types and values
    @Test
    public void testCredentialManagerSubjectAltNameMultiple() throws NamingException, ParseException, IOException {
        
        SubjectAlternativeNameType subj = new SubjectAlternativeNameType();
        subj.getDirectoryname().add(dir);
        subj.getDns().add(dns);
        subj.getEmail().add(email);
        subj.getIpaddress().add(ip);
        subj.getRegisteredid().add(reg);
        subj.getUri().add(uri);
        //subj.getOthername().add(other);
        CredentialManagerSubjectAltName subjectAltName = new CredentialManagerSubjectAlternateNameImpl(subj);
        assertTrue("SubjectAlternativeNameType dir ", 
                subjectAltName.getValue().get(0).get(0).equals(dir) ); 
        assertTrue("SubjectAlternativeNameType dns ", 
                subjectAltName.getValue().get(1).get(0).equals(dns) ); 
        assertTrue("SubjectAlternativeNameType email ", 
                subjectAltName.getValue().get(2).get(0).equals(email) ); 
        assertTrue("SubjectAlternativeNameType ip ", 
                subjectAltName.getValue().get(3).get(0).equals(ip) ); 
        assertTrue("SubjectAlternativeNameType reg ", 
                subjectAltName.getValue().get(4).get(0).equals(reg) ); 
        assertTrue("SubjectAlternativeNameType uri ", 
                subjectAltName.getValue().get(5).get(0).equals(uri) );
        /*
          assertTrue("SubjectAlternativeNameType other ", 
                subjectAltName.getValue().get(6).get(0).equals(other) );
        */

    }
    
    @Test
    public void SetterGetterTest() {
        CredentialManagerSubjectAlternateNameImpl altName = new CredentialManagerSubjectAlternateNameImpl(null);
        assertTrue(altName != null);
        altName.setType(null);
        assertTrue(altName.getType() != null); //getType will instantiate the List even if I set it to null before
        altName.setType(null);
        List<String> valuesList = new ArrayList<String>();
        valuesList.add("sameTypeValue1");
        valuesList.add("sameTypeValue2"); 
        //in this testcase doesn't matter how many values the same SAN type has, during the getType it will only check
        //how many entries this object class (CredentialManagerSubjectAlternateNameImpl) value field has.
        altName.getValue().add(valuesList);
        assertTrue(altName.getType().size() == 1 && altName.getType().get(0).name().equals(ALTERNATE_NAME_TYPE.NO_VALUE.toString()));
        assertTrue(altName.getSubjectAlternativeName() != null);
        
        CredentialManagerSubjectAlternateNameImpl altName1 = new CredentialManagerSubjectAlternateNameImpl(null);
        List<ALTERNATE_NAME_TYPE> typesList = new ArrayList<ALTERNATE_NAME_TYPE>();
        typesList.add(ALTERNATE_NAME_TYPE.NO_VALUE);
        altName1.setType(typesList);
        altName1.setValue(null);
        //the type field is populated with one entry
        assertTrue(altName1.getValue().size() == 1 && altName1.getValue().get(0).isEmpty()); 
        altName1.setValue(null);
        altName1.setType(new ArrayList<ALTERNATE_NAME_TYPE>());
        assertTrue(altName1.getValue() != null); //getValue will instantiate the List even if I set it to null before
    }
   
    
     
}
