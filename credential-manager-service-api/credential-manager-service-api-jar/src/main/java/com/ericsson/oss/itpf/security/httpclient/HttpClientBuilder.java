package com.ericsson.oss.itpf.security.httpclient;

import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.security.KeyManagementException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.UnrecoverableKeyException;
import java.security.cert.CertificateException;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Collections;
import java.util.List;

import javax.net.ssl.HostnameVerifier;
import javax.net.ssl.SSLSession;

import org.apache.http.conn.ssl.SSLConnectionSocketFactory;
import org.apache.http.conn.ssl.TrustSelfSignedStrategy;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.ssl.SSLContextBuilder;
import org.apache.http.ssl.SSLContexts;

/**
 * A wrapper for apache http client builder.
 * 
 * @author qdavges
 * 
 */
public class HttpClientBuilder {

    public CloseableHttpClient buildHttpClient() {
        final CloseableHttpClient httpClient = HttpClients.createDefault();
        return httpClient;
    }

    public Step1 buildHttpsClient() {
        return new Step1();
    }

    static class AllHostnameVerifier implements HostnameVerifier {
        @Override
        public boolean verify(final String hostname, final SSLSession sslSession) {
            return true;
        }
    }

    static class Step1 {
        final private SSLContextBuilder sslcontext = SSLContexts.custom();

        private Step1() {
        }

        final private List<String> allowedProtocols = new ArrayList<>();
        private HostnameVerifier hostnameVerifier = new AllHostnameVerifier();

        public Step1 addTrustore(final File trustore, final String trustStorePassword, final boolean trustSelfSIgnedertificates) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException {

            if (trustSelfSIgnedertificates) {
                sslcontext.loadTrustMaterial(trustore, trustStorePassword.toCharArray(), new TrustSelfSignedStrategy());
            } else {
                sslcontext.loadTrustMaterial(trustore, trustStorePassword.toCharArray());
            }
            return this;
        }

        public Step1 addKeystore(final File keystore, final String keyStorePassword) throws CertificateException, NoSuchAlgorithmException, KeyStoreException, IOException, UnrecoverableKeyException {

            final KeyStore identityStore = KeyStore.getInstance(KeyStore.getDefaultType());
            final FileInputStream instream = new FileInputStream(keystore);

            try {
                identityStore.load(instream, keyStorePassword.toCharArray());
            } finally {
                instream.close();
            }

            sslcontext.loadKeyMaterial(identityStore, keyStorePassword.toCharArray());

            return this;
        }

        public Step1 setAllowedProtocols(final String... protocols) {
            allowedProtocols.addAll(Arrays.asList(protocols));
            return this;
        }

        public Step1 setHostnameVerifier(final HostnameVerifier verifier) {
            hostnameVerifier = verifier;
            return this;
        }

        public CloseableHttpClient build() throws KeyManagementException, NoSuchAlgorithmException {

            if (allowedProtocols.isEmpty()) {
                Collections.addAll(allowedProtocols, new String[] { "TLSv1", "SSLv3" });
            }

            String[] strings = new String[allowedProtocols.size()];
            for (int i = 0; i < allowedProtocols.size(); i++) {
                strings[i] = allowedProtocols.get(i);
            }

            final SSLConnectionSocketFactory sslsf = new SSLConnectionSocketFactory(sslcontext.build(), strings, null, hostnameVerifier);

            final CloseableHttpClient httpclient = HttpClients.custom().setSSLSocketFactory(sslsf).build();

            return httpclient;
        }
    }
}
