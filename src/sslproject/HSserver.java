/*
 * To change this license header, choose License Headers in Project Properties.
 * To change this template file, choose Tools | Templates
 * and open the template in the editor.
 */
package sslproject;

/**
 *
 * @author SLam
 */
import java.security.*;
import java.io.*;
import java.security.cert.CertificateException;
import javax.net.*;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLServerSocket;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.net.*;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import javax.net.ssl.SSLServerSocketFactory;
import java.util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import static javax.crypto.Cipher.DECRYPT_MODE;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class HSserver {
    private SSLServerSocketFactory sslsockfactory;
    private SSLServerSocket serversock;
    private SSLSocket clientsock;
    private String version = "SSLv3";
    private int portnum = 1234;
    private int sessID;
    public int[] cCookie, sCookie;
    private static String[] availCiphersReceived;
    private String ver;
    
    private String ServerCertificateFilePath = "C:/Program Files/Java/jdk1.8.0_101/bin/sslserver.cer";
    private String keystorefilepath = "C:/Program Files/Java/jdk1.8.0_101/bin/keystore.pfx";
    private X509Certificate serverCert, clientCert;
    
    private byte[] serverHelloMessage;
    private byte[] serverCertificateBytes;
    private byte[] certRequest, clientCertBytes;
    private byte[] hellodone;
    
    PublicKey serverpubk, clientpubk;
    PrivateKey serverPrK;
    
    private SSLContext context;
    private InputStream bytesin;
    private OutputStream bytesout;
    SSLHandshake hsserver = new SSLHandshake();
    
    public void Init() throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, FileNotFoundException, CertificateException, UnrecoverableKeyException{
        context = hsserver.create_init_SSLContext(version, hsserver.KeyStoreFilePath);
        sslsockfactory = context.getServerSocketFactory();
        serversock = (SSLServerSocket)sslsockfactory.createServerSocket(portnum);
        System.out.println("Started up SSLServerSocket on port " + portnum + "...");
        clientsock = (SSLSocket)serversock.accept();
        System.out.println("Client connected.");
        bytesin = clientsock.getInputStream();
        bytesout = clientsock.getOutputStream();
    }
    
    byte[] rcvMsg () throws IOException{
        byte[] message = new byte[10000];
        bytesin.read(message);
        return message;
    }
    
    void rcvPMS(byte[] output) throws IOException{
        bytesin.read(output);
    }
    
    String ConvertBytetoString(byte[] bytemessage){
        StringBuilder bye = new StringBuilder();
        for (byte b: bytemessage){
            bye.append((char)b);
        }
        return bye.toString();
    }
    
    void processClientHello(String clienthello){
        //Processing each part of message split by ,
        String[] totalHello = clienthello.split(",");
        
        //version is the first part
        ver = totalHello[0];
        
        //session id is the second part
        sessID = Integer.parseInt(totalHello[1]);
        
        //cookie (random int[]) is the third part
        String[] totalCookie = totalHello[2].split(" ");
        
        cCookie = new int[totalCookie.length];
        for (int i = 0; i < totalCookie.length; i++){
            cCookie[i] = Integer.parseInt(totalCookie[i]);
        }
        
        //available ciphersuites is the fourth and last part
        String[] totalCiphers = totalHello[3].split("\n");
        availCiphersReceived = totalCiphers;
        
        System.out.println("Received parts of Client Hello: ");
        System.out.println("Client Version: " + ver + "\nSession ID: " + sessID);
        System.out.println("Client Cookie: ");
        for (int i = 0; i < cCookie.length; i++){
            if (i == cCookie.length-1){
                System.out.printf("%d",cCookie[i]);
            }
            else
            System.out.printf("%d, ",cCookie[i]);
        }
        System.out.println("\nReceived available ciphersuites: ");
        for (int i = 0; i <availCiphersReceived.length; i++){
            System.out.println(availCiphersReceived[i]);
        }
    }
    
    void SendSHello(String[] availcipher) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, FileNotFoundException, IOException, CertificateException, UnrecoverableKeyException{
        hsserver.serverHello(ver, availcipher);
        
        String msg = ver + ',' + sessID + ',';
        
        sCookie = hsserver.randomCookieGen();
        for (int i = 0; i < sCookie.length; i++){
            msg = msg + sCookie[i] + " ";
        }
        msg = msg + "," + hsserver.chosenCipher;
        
        System.out.println("This is the server's hello message: " + msg);
        serverHelloMessage = msg.getBytes();
        bytesout.write(serverHelloMessage);
    }
    
    void sendCertificate() throws CertificateException, IOException{
        serverCert = hsserver.generateX509cert(ServerCertificateFilePath);
        serverCertificateBytes = serverCert.getEncoded();
        bytesout.write(serverCertificateBytes);
        bytesout.flush();
    }
    
    void showMeYourCert() throws IOException{
        //String cCreq = hsserver.CertificateRequest(serverCert);
       String cCreq = "Give me your certificate!";
        System.out.println("This is the certificate request message to be sent to client: " + cCreq);
        certRequest = cCreq.getBytes();
        bytesout.write(certRequest, 0, certRequest.length);
        bytesout.flush();
    }
    
    void helloDone() throws IOException{
        String done = "Server done";
        hellodone = done.getBytes();
        bytesout.write(hellodone);
        bytesout.flush();
        System.out.println("Sent message to client: " + done);
    }
    
    X509Certificate receiveCert() throws IOException, CertificateException{
        clientCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(bytesin);
        clientCertBytes = clientCert.getEncoded();
        System.out.println("This is the received client certificate: " + clientCert.toString());
        return clientCert;
    }
    
     void generatePrivateKeyfromCertificate(X509Certificate cert) throws FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableKeyException, UnrecoverableEntryException{
        //TO DO: Generate key pair from given X509Certificate to be used in RSA asymmetric encryption/decrption for client/server verification/communication purposes.
        //loading keystore
        KeyStore keyStore = KeyStore.getInstance("PKCS12");
        
        //really essentially I'm just accessing the keystore.jks file I have in
        //that KeyStoreFilePath file
        //....why yes, I made the password to my alias -testKey "password"....If you made it differently, then change this
        char[] password = "password".toCharArray();
        java.io.FileInputStream fis = null;
        try {
            fis = new java.io.FileInputStream(keystorefilepath);
            keyStore.load(fis, password);            
        } finally {
            if (fis != null){
                fis.close();
            }
        }
       serverPrK = (PrivateKey)keyStore.getKey("sslserver", password);
       serverpubk = cert.getPublicKey();
    }
     
     byte[] decryptRSAPrK(byte[] message) throws InvalidKeyException, IllegalBlockSizeException, BadPaddingException, IOException, FileNotFoundException, NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableEntryException, NoSuchPaddingException {
         generatePrivateKeyfromCertificate(serverCert);
         Cipher RSACipher = Cipher.getInstance("RSA");
         RSACipher.init(DECRYPT_MODE, serverPrK);
         byte[] decryptedmsg = RSACipher.doFinal(message);
         return decryptedmsg;
     }
     
     byte[] decryptRSAPuK(byte[] input) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
         PublicKey clientpubk = clientCert.getPublicKey();
         Cipher RSACipher = Cipher.getInstance("RSA");
         RSACipher.init(DECRYPT_MODE, clientpubk);
         byte[] decryptedmsg = RSACipher.doFinal(input);
         return decryptedmsg;
     }
     
     void rcvChangeCipherSpec() throws IOException{
         if (bytesin.read() == (byte)1){
             System.out.println("Change cipher spec message from client was received.");
         }
     }
     
     void ChangeCipherSpec() throws IOException {  
        byte message = (byte)1;
        bytesout.write(message);
    }
    
    public static void main(String[]args)throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, FileNotFoundException, CertificateException, UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnrecoverableEntryException{
        HSserver server = new HSserver();
        server.Init();
        
        /**SSL HANDSHAKE: part 1**/
        byte[] clientHello = server.rcvMsg();

        String clientshello = server.ConvertBytetoString(clientHello);
        System.out.println("This is the client hello received: "+ clientshello);
        server.processClientHello(clientshello);
        
        server.SendSHello(availCiphersReceived);
        
        /*SSL HANDSHAKE: part 2*/
        server.sendCertificate();
        server.showMeYourCert();
        server.helloDone();
        
        /*SSL HANDSHAKE: part 3*/
        //TODO: receive all client messages.
        //first message: client's X509 certificate
        server.receiveCert();
        
        //second message: pre-master secret, encrypted in server's public key. Must decrypt with server's private key from server's X509Certificate.
        byte[] encryptedPMS = new byte[256];
        server.rcvPMS(encryptedPMS);
        byte[] PMS = server.decryptRSAPrK(encryptedPMS);
        
        //Third message: clientverifymsg.
        //Verify client's certificate by decrypting clientverifymsg with client's public key from client's X509Certificate.
        byte[] encryptedclientverifymsg = server.rcvMsg();
        byte[] clientverifymsg = server.decryptRSAPuK(encryptedclientverifymsg);
        
        
        /*SSL HANDSHAKE: part 4*/
        
        //receive client's change_cipher_spec message
        server.rcvChangeCipherSpec();
        //receive client's finished_message
        byte[] encrypted_clientfinishedmessage = server.rcvMsg();
        
        //send change_cipher_spec; message contents is a single byte, value of '1'
        server.ChangeCipherSpec();
        //send finished_message = concat of two values: MD5hash size[16] and SHAhash size [20]
        //MD5(mastersecret + pad2 + SHA(hsmessages + senderid + mastersecret + pad1))
        //SHA(mastersecret + pad2 + SHA(hsmessages + senderid + mastersecret + pad1))
        
    }
}
