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

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;
import org.xml.sax.SAXException;

import com.ericsson.oss.itpf.security.credmservice.exceptions.CredentialManagerCategoriesException;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.category.ObjectFactory;
import com.ericsson.oss.itpf.security.credmservice.model.xmlbeans.category.XmlCategory;

public class AppCategoryXmlConfiguration {

    private static final Logger log = LoggerFactory.getLogger(AppCategoryXmlConfiguration.class);

    private XmlCategory categories;

    private final String xmlFilePath;

    @SuppressWarnings("unchecked")
    public AppCategoryXmlConfiguration(final File xmlPAth) throws CredentialManagerCategoriesException {

        final Properties prop = PropertiesReader.getConfigProperties();

        xmlFilePath = (xmlPAth.getPath());

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
            Schema schema = null;

            try {
                try {
                    schema = schemaFactory.newSchema(FileSearch.getFile(prop.getProperty("path.xml.categories.schema")));
                } catch (final Exception ex) {
                    schema = schemaFactory.newSchema(AppCategoryXmlConfiguration.class.getClassLoader().getResource(prop.getProperty("path.xml.categories.schema")));
                }

            } catch (final SAXException e) {
                // LOG.error(Logger.getLogMessage(Logger.LOG_ERROR_READ_XSD_FILE),
                // prop.getProperty("path.xml.schema"));
                log.debug("AppCategoryXmlConfiguration: JAXB error reading CategoriesSchema.xsd ");
                throw new CredentialManagerCategoriesException(e.getCause());

            }
            unmarshaller.setSchema(schema);

            final JAXBElement<XmlCategory> unmarshalledObject = (JAXBElement<XmlCategory>) unmarshaller.unmarshal(xmlPAth);

            categories = unmarshalledObject.getValue();

        } catch (final JAXBException e) {

            log.debug("AppCategoryXmlConfiguration: JAXB error unmarshalling CategoriesSchema.xsd ");
            throw new CredentialManagerCategoriesException(e.getCause());
        }

    }

    public List<String> getXmlCategories() {
        return categories.getCategoryNameList();
    }

    /*
     * gets the category used for CredM Cli entities
     */
    public String getServiceCategory() {
        return categories.getServiceCategoryName();
    }

    /*
     * gets the undefined category (should be defined by PKI)
     */
    public String getUndefinedCategory() {
        return categories.getUndefinedCategoryName();
    }

    public String getXmlFilePath() {
        return xmlFilePath;
    }

}
