package com.ericsson.oss.itpf.security.credmservice.api.model;

import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

public class CredentialManagerCRLDistributionPointsTest {

    @Test
    public void equalsPointSTest() {
        CredentialManagerCRLDistributionPoints crlDPs = new CredentialManagerCRLDistributionPoints();
        assertTrue(crlDPs.equals(crlDPs));
        CredentialManagerSubject subj = new CredentialManagerSubject();
        assertTrue(!crlDPs.equals(subj));
        assertTrue(!crlDPs.equals(null));
        CredentialManagerCRLDistributionPoints crlDPs2 = new CredentialManagerCRLDistributionPoints();
        crlDPs.setCRLDistributionPoints(null);
        crlDPs2.setCRLDistributionPoints(null);
        assertTrue(crlDPs.equals(crlDPs2));
        List<CredentialManagerCRLDistributionPoint> list2 = new ArrayList<CredentialManagerCRLDistributionPoint>();
        crlDPs2.setCRLDistributionPoints(list2);
        assertTrue(!crlDPs.equals(crlDPs2));
        List<CredentialManagerCRLDistributionPoint> list1 = new ArrayList<CredentialManagerCRLDistributionPoint>();
        crlDPs.setCRLDistributionPoints(list1);
        assertTrue(crlDPs.equals(crlDPs2));
        
        CredentialManagerCRLDistributionPoint crlDistPoint1 = new CredentialManagerCRLDistributionPoint();
        list2.add(crlDistPoint1);
        assertTrue(!crlDPs.equals(crlDPs2));
        list1.add(crlDistPoint1);
        crlDPs.hashCode();
        assertTrue(crlDPs.equals(crlDPs2));
        crlDPs.setCRLDistributionPoints(null);
        assertTrue(crlDPs.hashCode() != crlDPs2.hashCode());
    }
    
    @Test
    public void equalsSinglePointTest() {
        CredentialManagerCRLDistributionPoint crl1 = new CredentialManagerCRLDistributionPoint();
        assertTrue(!crl1.equals(null));
        assertTrue(!crl1.equals(new CredentialManagerCRLDistributionPoints()));
        crl1.setCRLIssuer(null);
        crl1.setDistributionPointName(null);
        crl1.setReasonFlag(null);
        CredentialManagerCRLDistributionPoint crl2 = new CredentialManagerCRLDistributionPoint();
        crl2.setCRLIssuer(null);
        crl2.setDistributionPointName(null);
        crl2.setReasonFlag(null);
        assertTrue(crl1.equals(crl2) && (crl1.hashCode() == crl2.hashCode()));
        
        crl2.setCRLIssuer("test2");
        assertTrue(!crl1.equals(crl2));
        crl1.setCRLIssuer("test1");
        assertTrue(!crl1.equals(crl2));
        crl1.setCRLIssuer("test2");

        CredentialManagerDistributionPointName dpn = new CredentialManagerDistributionPointName();
        dpn.setNameRelativeToCRLIssuer("CRLIssuer");
        crl2.setDistributionPointName(dpn);
        assertTrue(!crl1.equals(crl2));
        crl1.setDistributionPointName(new CredentialManagerDistributionPointName());
        assertTrue(!crl1.equals(crl2));
        crl1.setDistributionPointName(dpn);

        crl1.setReasonFlag(CredentialManagerReasonFlag.AA_COMPROMISE);
        crl2.setReasonFlag(CredentialManagerReasonFlag.KEY_COMPROMISE);
        assertTrue(!crl1.equals(crl2));
        crl2.setReasonFlag(CredentialManagerReasonFlag.AA_COMPROMISE);
        assertTrue(crl1.hashCode() == crl2.hashCode());

    }
    
    @Test
    public void equalsCMDistributionPointNametest() {
        
        CredentialManagerDistributionPointName cmDPointName = new CredentialManagerDistributionPointName();
        assertTrue(!cmDPointName.equals(null));
        assertTrue(!cmDPointName.equals(new CredentialManagerSubject()));
        CredentialManagerDistributionPointName cmDPointName2 = new CredentialManagerDistributionPointName();
        cmDPointName.setFullName(null);
        cmDPointName2.setFullName(null);
        assertTrue(cmDPointName.equals(cmDPointName2));
        cmDPointName2.setFullName(new ArrayList<String>());
        assertTrue(!cmDPointName.equals(cmDPointName2));
        cmDPointName.setFullName(new ArrayList<String>());
        cmDPointName2.getFullName().add("elem1");
        assertTrue(!cmDPointName.equals(cmDPointName2));
        cmDPointName.getFullName().add("elem1");
        
        cmDPointName.setNameRelativeToCRLIssuer(null);
        cmDPointName2.setNameRelativeToCRLIssuer("crlIssuer2");
        assertTrue(!cmDPointName.equals(cmDPointName2));
        cmDPointName.setNameRelativeToCRLIssuer("crlIssuer");
        assertTrue(!cmDPointName.equals(cmDPointName2));
        cmDPointName2.setNameRelativeToCRLIssuer("crlIssuer");
        assertTrue(cmDPointName.equals(cmDPointName2));

    }
    
}
