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
package com.ericsson.oss.itpf.security.credmservice.entities.impl;

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

import com.ericsson.oss.itpf.security.credmservice.entities.api.CredentialManagerEntities;
import com.ericsson.oss.itpf.security.credmservice.entities.api.EntityConfigInformation;
import com.ericsson.oss.itpf.security.credmservice.entities.exceptions.CredentialManagerEntitiesException;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.ObjectFactory;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlCAEntity;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlEntity;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.entity.XmlPKIEntities;
import com.ericsson.oss.itpf.security.credmservice.util.FileSearch;
import com.ericsson.oss.itpf.security.credmservice.util.PropertiesReader;

public class AppEntityXmlConfiguration implements EntityConfigInformation {

    XmlPKIEntities pkiEntities;

    private String xmlFilePath;

    @SuppressWarnings("unchecked")
    public AppEntityXmlConfiguration(final File xmlPAth) throws CredentialManagerEntitiesException {

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
                    schema = schemaFactory.newSchema(FileSearch.getFile(prop.getProperty("path.xml.entities.schema")));
                } catch (final Exception ex) {
                    schema = schemaFactory.newSchema(AppEntityXmlConfiguration.class.getClassLoader().getResource(prop.getProperty("path.xml.entities.schema")));
                }

            } catch (final SAXException e) {
                // LOG.error(Logger.getLogMessage(Logger.LOG_ERROR_READ_XSD_FILE),
                // prop.getProperty("path.xml.schema"));
                throw new CredentialManagerEntitiesException(e.getCause());
            }
            unmarshaller.setSchema(schema);

            final JAXBElement<XmlPKIEntities> unmarshalledObject = (JAXBElement<XmlPKIEntities>) unmarshaller.unmarshal(xmlPAth);

            pkiEntities = unmarshalledObject.getValue();

        } catch (final JAXBException e) {
            // LOG.error(Logger.getLogMessage(Logger.LOG_ERROR_READ_APPFILE),
            // xmlPAth.getAbsolutePath());

            throw new CredentialManagerEntitiesException(e.getCause());
        }
        // LOG.info(Logger.getLogMessage(Logger.LOG_INFO_READ_END_APPFILE),
        // xmlPAth.getAbsolutePath());

    }

    /**
     * @return the AppEntities
     */
    private CredentialManagerEntities getAppEntities() {
        try {
            return new CredentialManagerEntitiesImpl(pkiEntities);
        } catch (final CredentialManagerEntitiesException e) {

            e.printStackTrace();
        }

        return null;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.credmservice.entities.api. EntityConfigInformation#getEntitiesInfo()
     */
    @Override
    public List<XmlEntity> getEntitiesInfo() {

        if (this.getAppEntities() != null) {
            return getAppEntities().getEntities();
        }

        return null;
    }

    /*
     * (non-Javadoc)
     *
     * @see com.ericsson.oss.itpf.security.credmservice.entities.api. EntityConfigInformation#getCAEntitiesInfo()
     */
    @Override
    public List<XmlCAEntity> getCAEntitiesInfo() {

        if (this.getAppEntities() != null) {
            return getAppEntities().getCAEntities();
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
    private void setXmlFilePath(final String xmlFilePath) {
        this.xmlFilePath = xmlFilePath;
    }

}
