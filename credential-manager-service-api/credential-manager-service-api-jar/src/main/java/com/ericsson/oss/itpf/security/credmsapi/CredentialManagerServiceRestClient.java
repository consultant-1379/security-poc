package com.ericsson.oss.itpf.security.credmsapi;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.ObjectInput;
import java.io.ObjectInputStream;
import java.io.UnsupportedEncodingException;
import java.net.InetAddress;
import java.net.UnknownHostException;
import java.security.cert.CertificateEncodingException;
import java.util.Map;

import javax.ws.rs.core.MediaType;
import javax.xml.bind.DatatypeConverter;

import org.apache.http.HttpEntity;
import org.apache.http.HttpHost;
import org.apache.http.ParseException;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpGet;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.client.methods.HttpRequestBase;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.util.EntityUtils;
import org.bouncycastle.pkcs.PKCS10CertificationRequest;
import org.apache.logging.log4j.LogManager;
import org.apache.logging.log4j.Logger;

import com.ericsson.oss.itpf.security.credmsapi.business.utils.ErrorMsg;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerCertificateAuthority;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerEntity;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerPIBParameters;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerProfileInfo;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerTrustMaps;
import com.ericsson.oss.itpf.security.credmservice.api.model.CredentialManagerX509Certificate;
import com.ericsson.oss.itpf.security.credmservice.api.rest.model.CreateAndGetEndEntityRequest;
import com.ericsson.oss.itpf.security.credmservice.api.rest.model.GetCertificateRequest;
import com.ericsson.oss.itpf.security.credmservice.api.rest.model.GetCertificateResponse;
import com.ericsson.oss.itpf.security.credmservice.api.rest.model.GetTrustResponse;
import com.ericsson.oss.itpf.security.httpclient.HttpClientBuilder;
import com.fasterxml.jackson.core.JsonProcessingException;
import com.fasterxml.jackson.databind.ObjectMapper;

/**
 * Created by enmadmin on 4/7/15.
 */
public class CredentialManagerServiceRestClient {

    private static final Logger LOG = LogManager.getLogger(CredentialManagerServiceRestClient.class);

    public static final String GET_PROFILE_PATH = "/credential-manager-service/rest/1.0/profile/get";
    public static final String CREATE_AND_GET_END_ENTITY_PATH = "/credential-manager-service/rest/1.0/entity/create";
    private static final String GET_CERTIFICATE_PATH = "/credential-manager-service/rest/1.0/certificate/issue";
    private static final String GET_TRUST_PATH = "/credential-manager-service/rest/1.0/trust/get";
    public static final String GET_PIB_PARAMETERS_PATH = "/credential-manager-service/rest/1.0/pib/get";

    private final String hostname;
    private final int port;
    private final CloseableHttpClient httpClient;
    private final HttpHost httpHost;

    private String myHostName;

    public CredentialManagerServiceRestClient(final String hostname, final int port) {
        this.hostname = hostname;
        this.port = port;
        this.httpClient = new HttpClientBuilder().buildHttpClient();
        this.httpHost = new HttpHost(hostname, port);

        try {
            myHostName = InetAddress.getLocalHost().getHostName();
        } catch ( UnknownHostException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            myHostName = "Not found";
        }

    }

    public CredentialManagerServiceRestClient(final String address) {
        final String[] parameters = address.split(":");
        if (parameters.length != 2) {
            LOG.error(ErrorMsg.API_ERROR_SERVICE_ADDRESS_FORMAT, address);
            throw new ParseException(address);
        }
        this.hostname = parameters[0];
        this.port = Integer.parseInt(parameters[1]);
        this.httpClient = new HttpClientBuilder().buildHttpClient();

        this.httpHost = new HttpHost(this.hostname, this.port);

        try {
            myHostName = InetAddress.getLocalHost().getHostName();
        } catch ( UnknownHostException e) {
            // TODO Auto-generated catch block
            e.printStackTrace();
            myHostName = "Not found";
        }

    }

    public CredentialManagerProfileInfo getProfile() {
        final HttpGet httpGet = new HttpGet(GET_PROFILE_PATH);

        httpGet.addHeader("X-Tor-UserID", "credentialManagerApi: " + myHostName);

        final RequestConfig requestConfig = RequestConfig.custom().setConnectTimeout(1000).build();
        httpGet.setConfig(requestConfig);

        CredentialManagerProfileInfo response;
        response = this.invokeHttpMethod(CredentialManagerProfileInfo.class, httpGet);
        return response;

    }

    public CredentialManagerEntity createAndGetEndEntity(final String reqHostName, final String reqPassword) {
        final HttpPost httpPost = new HttpPost(CREATE_AND_GET_END_ENTITY_PATH);
        httpPost.setHeader("Content-Type", MediaType.APPLICATION_JSON);

        httpPost.addHeader("X-Tor-UserID", "credentialManagerApi: " + myHostName);

        final CreateAndGetEndEntityRequest endEntityRequest = new CreateAndGetEndEntityRequest();
        endEntityRequest.setHostname(reqHostName);
        endEntityRequest.setPassword(reqPassword);
        final HttpEntity httpEntity = jsonMarshall(endEntityRequest);
        httpPost.setEntity(httpEntity);
        CredentialManagerEntity response;
        try {
            response = this.invokeHttpMethod(CredentialManagerEntity.class, httpPost);
        } catch (final Exception e) {
            // TODO Auto-generated catch block
            // e.printStackTrace();
            return null;
        }
        return response;
    }

    public CredentialManagerX509Certificate[] getCertificate(final PKCS10CertificationRequest request) {
        final HttpPost httpPost = new HttpPost(GET_CERTIFICATE_PATH);
        httpPost.setHeader("Content-Type", MediaType.APPLICATION_JSON);

        httpPost.addHeader("X-Tor-UserID", "credentialManagerApi: " + myHostName);

        final GetCertificateRequest getCertificateRequest = new GetCertificateRequest();
        String csrEncoded;
        try {
            csrEncoded = new String(DatatypeConverter.printBase64Binary(request.getEncoded()));
        } catch (final IOException e2) {
            LOG.error(ErrorMsg.API_ERROR_SERVICE_GET_CSR);
            //			e2.printStackTrace();
            return null;
        }
        getCertificateRequest.setCsrEncoded(csrEncoded);
        final HttpEntity httpEntity = jsonMarshall(getCertificateRequest);
        httpPost.setEntity(httpEntity);

        GetCertificateResponse response;
        try {
            response = this.invokeHttpMethod(GetCertificateResponse.class, httpPost);
        } catch (final Exception e1) {
            // TODO Auto-generated catch block
            // e1.printStackTrace();
            return null;
        }

        final CredentialManagerX509Certificate[] certificate = new CredentialManagerX509Certificate[response.getCertificate().length];
        try {
            for (int certsCounter = 0; certsCounter < response.getCertificate().length; certsCounter++) {
                certificate[certsCounter] = new CredentialManagerX509Certificate(DatatypeConverter.parseBase64Binary(response.getCertificate()[certsCounter]));
            }
        } catch (final CertificateEncodingException e) {
            LOG.error(ErrorMsg.API_ERROR_SERVICE_GET_CERT);
            //e.printStackTrace();
            return null;
        }
        return certificate;
    }

    public CredentialManagerTrustMaps getTrust() {
        final HttpGet httpGet = new HttpGet(GET_TRUST_PATH);
        httpGet.addHeader("X-Tor-UserID", "credentialManagerApi: " + myHostName);

        GetTrustResponse response;
        try {
            response = this.invokeHttpMethod(GetTrustResponse.class, httpGet);
        } catch (final Exception e1) {
            // TODO Auto-generated catch block
            // e1.printStackTrace();
            return null;
        }

        //final Map<String, CredentialManagerCertificateAuthority> trust = new HashMap<String, CredentialManagerCertificateAuthority>();

        final CredentialManagerTrustMaps trustMaps = new CredentialManagerTrustMaps();
        // trust = new
        // CredentialManagerX509Certificate(DatatypeConverter.parseBase64Binary(response.getCertificate()));
        for (final Map.Entry<String, String> entry : response.getIntTrusts().entrySet()) {
            // CredentialManagerCertificateAuthority ca = new
            // CredentialManagerCertificateAuthority(name);

            System.out.println("REST: internal trust " + entry.getKey() /* + "/" + entry.getValue() */);
            // ByteArrayOutputStream bos = new ByteArrayOutputStream();
            // ObjectOutput out = null;
            // CredentialManagerCertificateAuthority ca = entry.getValue();
            final ByteArrayInputStream bis = new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(entry.getValue()));
            ObjectInput in = null;

            try {
                in = new ObjectInputStream(bis);
            } catch (final IOException e) {
                LOG.error(ErrorMsg.API_ERROR_SERVICE_GET_TRUSTENTRY, entry.getValue());
                //e.printStackTrace();
                return null;
            }
            CredentialManagerCertificateAuthority ca = null;
            try {
                ca = (CredentialManagerCertificateAuthority) in.readObject();
            } catch (ClassNotFoundException | IOException e) {
                LOG.error(ErrorMsg.API_ERROR_SERVICE_GET_CA);
                //e.printStackTrace();
                return null;
            }

            // byte[] caBytes = bos.toByteArray();
            trustMaps.getInternalCATrustMap().put(entry.getKey(), ca);
        }

        for (final Map.Entry<String, String> entry : response.getExtTrusts().entrySet()) {
            // CredentialManagerCertificateAuthority ca = new
            // CredentialManagerCertificateAuthority(name);

            System.out.println("REST: external trust " + entry.getKey() /* + "/" + entry.getValue() */);
            // ByteArrayOutputStream bos = new ByteArrayOutputStream();
            // ObjectOutput out = null;
            // CredentialManagerCertificateAuthority ca = entry.getValue();
            final ByteArrayInputStream bis = new ByteArrayInputStream(DatatypeConverter.parseBase64Binary(entry.getValue()));
            ObjectInput in = null;

            try {
                in = new ObjectInputStream(bis);
            } catch (final IOException e) {
                LOG.error(ErrorMsg.API_ERROR_SERVICE_GET_TRUSTENTRY, entry.getValue());
                //e.printStackTrace();
                return null;
            }
            CredentialManagerCertificateAuthority ca = null;
            try {
                ca = (CredentialManagerCertificateAuthority) in.readObject();
            } catch (ClassNotFoundException | IOException e) {
                LOG.error(ErrorMsg.API_ERROR_SERVICE_GET_CA);
                //e.printStackTrace();
                return null;
            }

            // byte[] caBytes = bos.toByteArray();
            trustMaps.getExternalCATrustMap().put(entry.getKey(), ca);
        }

        return trustMaps;
    }

    private <T> T invokeHttpMethod(final Class<T> clazz, final HttpRequestBase request) {

        LOG.info(String.format("invoking %s on client %s", request.toString(), this.httpClient.toString()));

        try (CloseableHttpResponse httpResponse = this.httpClient.execute(this.httpHost, request);) {
            // byte[] byteArray =
            // EntityUtils.toByteArray(httpResponse.getEntity()/*, "UTF-8"*/);
            // LOG.info("received Http response: " + httpResponse);
            //
            // ObjectInputStream objectInputStream = new ObjectInputStream(
            // new ByteArrayInputStream(/*toString.getBytes()*/byteArray));
            // T returnObj = clazz.cast(objectInputStream.readObject());
            final String toString = EntityUtils.toString(httpResponse.getEntity()/*
                                                                                  * , "UTF-8"
                                                                                  */);
            final T returnObj = new ObjectMapper().readValue(toString, clazz);
            return returnObj;
        } catch (final IOException /* | ClassNotFoundException */ e) {
            LOG.debug(ErrorMsg.API_ERROR_SERVICE_HTTP_INVOKE, request.toString(), this.httpHost.toString());
            throw new IllegalStateException(e);
        }
    }

    public static <T> T jsonUnmarshall(final HttpEntity entity, final Class<T> clazz) throws ParseException, IOException {
        final String result = EntityUtils.toString(entity, "UTF-8");

        final ObjectMapper mapper = new ObjectMapper();

        return mapper.readValue(result, clazz);
    }

    public static HttpEntity jsonMarshall(final Object params) {
        final ObjectMapper mapper = new ObjectMapper();
        try {
            final HttpEntity entityRequest = new StringEntity(new String(mapper.writeValueAsBytes(params)));
            return entityRequest;
        } catch (final JsonProcessingException e) {
            LOG.error(ErrorMsg.API_ERROR_SERVICE_JMARSHAL_PROCESSING);
            //e.printStackTrace();
        } catch (final UnsupportedEncodingException e) {
            LOG.error(ErrorMsg.API_ERROR_SERVICE_JMARSHAL_ENCODING);
            //e.printStackTrace();
        }
        return null;
    }

    /**
     * @return
     */
    public CredentialManagerPIBParameters getPibParameters() {
        final HttpGet httpGet = new HttpGet(GET_PIB_PARAMETERS_PATH);

        httpGet.addHeader("X-Tor-UserID", "credentialManagerApi: " + myHostName);
        final RequestConfig requestConfig = RequestConfig.custom().setConnectTimeout(1000).build();
        httpGet.setConfig(requestConfig);

        CredentialManagerPIBParameters response;
        response = this.invokeHttpMethod(CredentialManagerPIBParameters.class, httpGet);
        return response;
    }

}
