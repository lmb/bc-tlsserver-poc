import org.bouncycastle.crypto.params.AsymmetricKeyParameter;
import org.bouncycastle.crypto.prng.ThreadedSeedGenerator;
import org.bouncycastle.crypto.tls.*;
import org.bouncycastle.crypto.tls.Certificate;
import org.bouncycastle.crypto.util.PrivateKeyFactory;

import java.io.*;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.cert.X509Certificate;

public class TlsServer {
    private static SecureRandom createSecureRandom()
    {
        /*
         * We use our threaded seed generator to generate a good random seed. If the user has a
         * better random seed, he should use the constructor with a SecureRandom.
         */
        ThreadedSeedGenerator tsg = new ThreadedSeedGenerator();
        SecureRandom random = new SecureRandom();

        /*
         * Hopefully, 20 bytes in fast mode are good enough.
         */
        random.setSeed(tsg.generateSeed(20, true));

        return random;
    }

    public static KeyStore loadDefaultKeyStore() throws KeyStoreException, IOException, CertificateException, NoSuchAlgorithmException {
        FileInputStream is = new FileInputStream(System.getProperty("javax.net.ssl.keyStore"));
        KeyStore ks = KeyStore.getInstance("jks");
        ks.load(is, System.getProperty("javax.net.ssl.keyStorePassword").toCharArray());
        return ks;
    }

    public static KeyStore.PrivateKeyEntry loadPrivateKey(String alias, KeyStore ks) throws UnrecoverableEntryException, NoSuchAlgorithmException, KeyStoreException {
        String password = System.getProperty("javax.net.ssl.keyStorePassword");
        return (KeyStore.PrivateKeyEntry)ks.getEntry(alias, new KeyStore.PasswordProtection(password.toCharArray()));
    }

    public static org.bouncycastle.crypto.tls.Certificate getCert(KeyStore.PrivateKeyEntry key) throws CertificateEncodingException, IOException {
        org.bouncycastle.asn1.x509.Certificate x509cert = org.bouncycastle.asn1.x509.Certificate.getInstance(((X509Certificate)key.getCertificate()).getEncoded());
        return new org.bouncycastle.crypto.tls.Certificate(new org.bouncycastle.asn1.x509.Certificate[] {x509cert});
    }

    public static AsymmetricKeyParameter getKeys(KeyStore.PrivateKeyEntry key) throws IOException {
        return PrivateKeyFactory.createKey(key.getPrivateKey().getEncoded());
    }

    public static void main(String [ ] args)
    {
        try {
            ServerSocket serverSocket = new ServerSocket(9999);

            System.out.println("Listening");
            System.out.println(KeyStore.getDefaultType());

            KeyStore ks = loadDefaultKeyStore();
            KeyStore.PrivateKeyEntry key = loadPrivateKey("apollo-server", ks);
            final org.bouncycastle.crypto.tls.Certificate cert = getCert(key);
            final AsymmetricKeyParameter bcKey = getKeys(key);

            while (true) {
                try {
                    Socket clientSocket = serverSocket.accept();
                    TlsServerProtocol clientProtocol = new TlsServerProtocol(clientSocket.getInputStream(),
                            clientSocket.getOutputStream(), createSecureRandom());
                    DefaultTlsServer tlsServer = new DefaultTlsServer() {
                        @Override
                        protected TlsSignerCredentials getRSASignerCredentials() {
                            return new DefaultTlsSignerCredentials(context, cert, bcKey);
                        }

                        @Override
                        protected TlsEncryptionCredentials getRSAEncryptionCredentials() {
                            return new DefaultTlsEncryptionCredentials(context, cert, bcKey);
                        }

                        @Override
                        public void notifySecureRenegotiation(boolean secureRenegotiation) throws IOException {
                            // This is required, since the default implementation throws an error if secure reneg is not
                            // supported
                        }
                    };
                    clientProtocol.accept(tlsServer);
                    System.out.println("Have connection");

                    // So, without this sleep bouncy castle throws an internal error. Great!
                    Thread.sleep(100);
                    byte[] dummy = new byte[2048]; // Should be two records
                    OutputStream outputStream = clientProtocol.getOutputStream();
                    outputStream.write(dummy);

                    InputStream in = clientProtocol.getInputStream();
                    int read;
                    while ((read = in.read(dummy)) != -1) {
                        System.out.println(String.format("Got %d bytes", read));
                    }

                    System.out.println("Disconnected");
                } catch (IOException e) {
                    System.out.println("Client exited unclean");
                }
            }
        } catch (Exception exception) {
            exception.printStackTrace();
        }
    }
}
