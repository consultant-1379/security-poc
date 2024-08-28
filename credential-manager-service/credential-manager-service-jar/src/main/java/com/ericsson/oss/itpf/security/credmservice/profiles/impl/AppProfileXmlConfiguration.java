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
package com.ericsson.oss.itpf.security.credmservice.profiles.impl;

import java.io.File;
import java.util.List;
import java.util.Properties;

import javax.xml.XMLConstants;
import javax.xml.bind.JAXBContext;
import javax.xml.bind.JAXBElement;
import javax.xml.bind.JAXBException;
import javax.xml.bind.Unmarshaller;
import javax.xml.validation.Schema;
import javax.xml.validation.SchemaFactory;

import org.xml.sax.SAXException;

import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.ObjectFactory;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlCertificateProfile;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlEntityProfile;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlProfiles;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.XmlTrustProfile;
import com.ericsson.oss.itpf.security.credmservice.profiles.api.CredentialManagerProfiles;
import com.ericsson.oss.itpf.security.credmservice.profiles.api.ProfileConfigInformation;
import com.ericsson.oss.itpf.security.credmservice.profiles.exceptions.CredentialManagerProfilesException;
import com.ericsson.oss.itpf.security.credmservice.util.FileSearch;
import com.ericsson.oss.itpf.security.credmservice.util.PropertiesReader;

public class AppProfileXmlConfiguration implements ProfileConfigInformation {

    // private static final org.slf4j.Logger LOG = Logger.getLogger();
    XmlProfiles profiles;

    private String xmlFilePath;

    @SuppressWarnings("unchecked")
    public AppProfileXmlConfiguration(final File xmlPAth) throws CredentialManagerProfilesException {
        super();

        final Properties prop = PropertiesReader.getConfigProperties();

        this.setXmlFilePath(xmlPAth.getPath());

        // LOG.info(Logger.getLogMessage(Logger.LOG_INFO_READ_START_APPFILE),
        // xmlPAth.getAbsolutePath());

        // LOG.debug(Logger.getLogMessage(Logger.LOG_DEBUG_READ_APPFILE),
        // xmlPAth.toString());

        try {
            JAXBContext jaxbContext;
            jaxbContext = JAXBContext.newInstance(ObjectFactory.class);
            Unmarshaller unmarshaller = null;

            unmarshaller = jaxbContext.createUnmarshaller();

            final SchemaFactory schemaFactory = SchemaFactory.newInstance(XMLConstants.W3C_XML_SCHEMA_NS_URI);
            Schema schema;

            try {
                try {
                    schema = schemaFactory.newSchema(FileSearch.getFile(prop.getProperty("path.xml.profiles.schema")));
                } catch (final Exception ex) {
                    schema = schemaFactory.newSchema(AppProfileXmlConfiguration.class.getClassLoader().getResource(prop.getProperty("path.xml.profiles.schema")));
                }

            } catch (final SAXException e) {
                // LOG.error(Logger.getLogMessage(Logger.LOG_ERROR_READ_XSD_FILE),
                // prop.getProperty("path.xml.schema"));
                throw new CredentialManagerProfilesException(e.getCause());
            }
            unmarshaller.setSchema(schema);

            final JAXBElement<XmlProfiles> unmarshalledObject = (JAXBElement<XmlProfiles>) unmarshaller.unmarshal(xmlPAth);

            profiles = unmarshalledObject.getValue();

        } catch (final JAXBException e) {
            // LOG.error(Logger.getLogMessage(Logger.LOG_ERROR_READ_APPFILE),
            // xmlPAth.getAbsolutePath());

            throw new CredentialManagerProfilesException(e.getCause());
        }
        // LOG.info(Logger.getLogMessage(Logger.LOG_INFO_READ_END_APPFILE),
        // xmlPAth.getAbsolutePath());

    }

    /**
     * @return the AppProfiles
     */
    private CredentialManagerProfiles getAppProfiles() {
        try {
            return new CredentialManagerProfilesImpl(profiles);
        } catch (final CredentialManagerProfilesException e) {

            e.printStackTrace();
        }

        return null;
    }

    @Override
    public List<XmlTrustProfile> getTrustProfilesInfo() {

        if (this.getAppProfiles() != null) {
            return getAppProfiles().getTrustProfiles();
        }
        return null;
    }

    @Override
    public List<XmlEntityProfile> getEntityProfilesInfo() {

        if (this.getAppProfiles() != null) {
            return getAppProfiles().getEntityProfiles();
        }
        return null;
    }

    @Override
    public List<XmlCertificateProfile> getCertificateProfilesInfo() {

        if (this.getAppProfiles() != null) {
            return getAppProfiles().getCertificateProfiles();
        }
        return null;
    }

    /**
     * @return the xmlFilePath
     */
    @Override
    public String getXmlFilePath() {
        return xmlFilePath;
    }

    /**
     * @param xmlFilePath
     *            the xmlFilePath to set
     */
    private void setXmlFilePath(final  String xmlFilePath) {
        this.xmlFilePath = xmlFilePath;
    }

}
