package com.ericsson.oss.itpf.security.credmservice.profilesUpgrade;

import static org.junit.Assert.assertTrue;

import java.util.ArrayList;
import java.util.List;

import org.junit.Test;

import com.ericsson.oss.itpf.security.credmservice.profilesUpgradeObjects.CredMServiceCAEntityUpdate;
import com.ericsson.oss.itpf.security.credmservice.profilesUpgradeObjects.CredMServiceCertificateProfileUpdate;
import com.ericsson.oss.itpf.security.credmservice.profilesUpgradeObjects.CredMServiceTrustProfileUpdate;
import com.ericsson.oss.itpf.security.pki.common.model.CertificateAuthority;
import com.ericsson.oss.itpf.security.pki.common.model.crl.CrlGenerationInfo;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.CAEntity;
import com.ericsson.oss.itpf.security.pki.manager.model.entities.ExtCA;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.CertificateProfile;
import com.ericsson.oss.itpf.security.pki.manager.model.profiles.TrustProfile;

public class CredMServiceUpdateObjectsTest {

    @Test
    public void testObjectProfile() {
        CredMServiceCAEntityUpdate cmCAEntityUpdate = new CredMServiceCAEntityUpdate();
        CredMServiceCertificateProfileUpdate cmCPUpdate = new CredMServiceCertificateProfileUpdate();
        CredMServiceTrustProfileUpdate cmTPUpdate = new CredMServiceTrustProfileUpdate();
        assertTrue(cmCAEntityUpdate!=null && cmCPUpdate!=null && cmTPUpdate!=null);
    }
    
    @Test
    public void testUpdateCAEntitycvn0 () {
        CAEntity caXml = new CAEntity();
        caXml.setCertificateAuthority(new CertificateAuthority());
        caXml.getCertificateAuthority().setName("caXml");
        CAEntity result = CredMServiceCAEntityUpdate.updateCvn_0(caXml);
        assertTrue(result == null);
        
        CAEntity ca1 = new CAEntity();
        ca1.setCertificateAuthority(new CertificateAuthority());
        ca1.getCertificateAuthority().setName("ca1");
        CAEntity ca2 = new CAEntity();
        ca2.setCertificateAuthority(new CertificateAuthority());
        ca2.getCertificateAuthority().setName("ca2");
        result = CredMServiceCAEntityUpdate.updateCvn_0(caXml,ca1,ca2);
        assertTrue(result == null);
        //from xml with content and from pki without
        List<CrlGenerationInfo> crlGenList = new ArrayList<CrlGenerationInfo>();
        crlGenList.add(new CrlGenerationInfo());
        caXml.getCertificateAuthority().setCrlGenerationInfo(crlGenList);
        result = CredMServiceCAEntityUpdate.updateCvn_0(caXml,ca1,null);
        assertTrue(result.getCertificateAuthority().getCrlGenerationInfo().size() == 1);
        //same but from pki empty
        ca1.getCertificateAuthority().setCrlGenerationInfo(new ArrayList<CrlGenerationInfo>());
        result = CredMServiceCAEntityUpdate.updateCvn_0(caXml,ca1,null);
        assertTrue(result.getCertificateAuthority().getCrlGenerationInfo().size() == 1);
        //from pki with content
        ca1.getCertificateAuthority().setCrlGenerationInfo(crlGenList);
        result = CredMServiceCAEntityUpdate.updateCvn_0(caXml,ca1,null);
        assertTrue(result == null);
        //from xml without and from pki empty
        ca1.getCertificateAuthority().setCrlGenerationInfo(new ArrayList<CrlGenerationInfo>());
        caXml.getCertificateAuthority().setCrlGenerationInfo(null);
        result = CredMServiceCAEntityUpdate.updateCvn_0(caXml,ca1,null);
        assertTrue(result == null);
        //from  xml empty from pki without
        caXml.getCertificateAuthority().setCrlGenerationInfo(new ArrayList<CrlGenerationInfo>());
        ca1.getCertificateAuthority().setCrlGenerationInfo(null);
        assertTrue(result == null);

    }
    
    @Test
    public void testUpdateCertProfilecvn0() {
        CertificateProfile cpXml = new CertificateProfile();
        cpXml.setId(12);
        cpXml.setName("cpXml");
        CertificateProfile cp1 = new CertificateProfile();
        cp1.setId(21);
        cp1.setName("cp1");
        CertificateProfile result = CredMServiceCertificateProfileUpdate.updateCvn_0(cpXml,cp1);
        assertTrue(result == null);
        result = CredMServiceCertificateProfileUpdate.updateCvn_0(cpXml,cp1,null);
        assertTrue(result.getName().equals(cpXml.getName()) && result.getId() == cp1.getId());
    }
    
    @Test
    public void testUpdateTrustProfilecvn0() {
        
        TrustProfile tpXml = new TrustProfile();
        TrustProfile tp1 = new TrustProfile();
        TrustProfile result = CredMServiceTrustProfileUpdate.updateCvn_0(tpXml, tp1);
        assertTrue(result == null);
        
        tpXml.setName("NotEPPKI");
        result = CredMServiceTrustProfileUpdate.updateCvn_0(tpXml, tp1, null);
        assertTrue(result == null);
        
        //VC_Root_CA_A1=ExtCA name default
        
        tpXml.setName("EPPKI_TP");
        result = CredMServiceTrustProfileUpdate.updateCvn_0(tpXml, tp1, null);
        assertTrue(result.getExternalCAs().get(0).getCertificateAuthority().getName().equals("VC_Root_CA_A1"));
        
        List<ExtCA> extCAlist = new ArrayList<ExtCA>();
        ExtCA extCA = new ExtCA();
        extCA.setCertificateAuthority(new CertificateAuthority());
        extCA.getCertificateAuthority().setName("FakeExtCA");
        extCAlist.add(extCA);
        tp1.setExternalCAs(extCAlist);
        result = CredMServiceTrustProfileUpdate.updateCvn_0(tpXml, tp1, null);
        assertTrue(result.getExternalCAs().get(0).getCertificateAuthority().getName().equals("FakeExtCA") &&
                result.getExternalCAs().get(1).getCertificateAuthority().getName().equals("VC_Root_CA_A1"));
        
        extCA.getCertificateAuthority().setName("VC_Root_CA_A1");
        result = CredMServiceTrustProfileUpdate.updateCvn_0(tpXml, tp1, null);
        assertTrue(result == null);

        
    }
    
    
}
