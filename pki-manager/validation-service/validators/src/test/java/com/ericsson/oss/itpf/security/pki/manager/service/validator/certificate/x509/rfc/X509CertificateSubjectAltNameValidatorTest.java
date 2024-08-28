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
package com.ericsson.oss.itpf.security.pki.manager.service.validator.certificate.x509.rfc;

import java.io.FileNotFoundException;
import java.security.cert.*;
import java.util.*;

import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.*;
import org.mockito.runners.MockitoJUnitRunner;
import org.slf4j.Logger;

import com.ericsson.oss.itpf.security.pki.common.model.certificate.extension.SubjectAltNameField;
import com.ericsson.oss.itpf.security.pki.common.util.constants.ErrorMessages;
import com.ericsson.oss.itpf.security.pki.manager.exception.security.certificate.certificatefield.certificateextension.InvalidSubjectAltNameExtension;
import com.ericsson.oss.itpf.security.pki.manager.service.validator.common.profile.SubjectAltNameValidator;
import com.ericsson.oss.itpf.security.pki.manager.validation.service.api.model.CACertificateValidationInfo;

@RunWith(MockitoJUnitRunner.class)
public class X509CertificateSubjectAltNameValidatorTest {

    @InjectMocks
    X509CertificateSubjectAltNameValidator CertificateSubjectAltNameValidator;

    @Mock
    SubjectAltNameValidator subjectAltNameValidator;
    @Mock
    Logger logger;
    @Mock
    X509Certificate x509Certificate;

    @Mock
    List subjectAltNameFieldType;
    
    @Mock
    SubjectAltNameField subjectAltNameField;
    
    Collection<List<?>> subjectAlternativeNames = new HashSet();
    
    private static String caName = "caName";
    
    @Test
    public void testvalidate() throws CertificateException, FileNotFoundException {
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");
        
        CACertificateValidationInfo caCertificateValidationInfo =   certificateBase.getRootCACertificateInfo(certificateToValidate);
        CertificateSubjectAltNameValidator.validate(caCertificateValidationInfo);
           
    }

    @Test(expected=InvalidSubjectAltNameExtension.class)
    public void testValidate_RFCException() throws CertificateException, FileNotFoundException {
    
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");
        Mockito.when(x509Certificate.getSubjectAlternativeNames()).thenThrow(InvalidSubjectAltNameExtension.class);
        CertificateSubjectAltNameValidator.validate(certificateBase.getRootCACertificateInfo(x509Certificate));
   
        Mockito.verify(logger).error(ErrorMessages.CERTIFICATE_PARSING_FAILED, " for CA {} ", caName, Matchers.anyObject());
    
    }
    @Test(expected=InvalidSubjectAltNameExtension.class)
    public void testValidate_CertificateException() throws CertificateException, FileNotFoundException {

        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");
        Mockito.when(x509Certificate.getSubjectAlternativeNames()).thenThrow(CertificateParsingException.class);
        CertificateSubjectAltNameValidator.validate(certificateBase.getRootCACertificateInfo(x509Certificate));
        Mockito.verify(logger).error(ErrorMessages.CERTIFICATE_PARSING_FAILED, " for CA {} ", caName, Matchers.anyObject());

        
    }
    @Test
    public void testValidate_RFCExceptio1() throws CertificateException, FileNotFoundException {
    	List<Integer> l=new ArrayList<Integer>();
    	HashMap<Integer, Integer> map=new HashMap<Integer, Integer>();
    	map.put(0,0);
    	map.put(1, 1);
    	map.put(2, 1);
    	map.put(4, 4);
    	map.put(5, 5);
    	map.put(6, 6);
    	map.put(8,8);
    	
    	
    	Iterator itr = (Iterator)map.keySet().iterator();
    	
    	while (itr.hasNext()) {
    		List<Integer> list=new ArrayList<Integer>();
    		Integer key = (Integer)itr.next();
    		Integer value =map.get(key);
			list.add(key);
			list.add(value);
			subjectAlternativeNames.add(list);
		}
    	
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");
        Mockito.when(x509Certificate.getSubjectAlternativeNames()).thenReturn(subjectAlternativeNames);
        CertificateSubjectAltNameValidator.validate(certificateBase.getRootCACertificateInfo(x509Certificate));
       
    }  
    
    


    @Mock
    X509Certificate x509Cert;

    @Test
    public void validate() throws CertificateException, FileNotFoundException {
        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");
        CertificateSubjectAltNameValidator.validate(certificateBase.getRootCACertificateInfo(certificateToValidate));
    }

    @Test
    public void validate_RFCException() throws CertificateException, FileNotFoundException {

        CertificateBase certificateBase = new CertificateBase();
        final X509Certificate certificateToValidate = certificateBase.getX509Certificate("ENM_RootCA10021.cer");
        CertificateSubjectAltNameValidator.validate(certificateBase.getRootCACertificateInfo(certificateToValidate));
    }
}
