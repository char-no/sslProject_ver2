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
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import javax.net.*;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import java.util.*;
import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import static javax.crypto.Cipher.ENCRYPT_MODE;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import java.nio.*;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.spec.InvalidKeySpecException;

public class HSclient {
    private static SSLSocket clientsock;
    private SSLSocketFactory sslsockfactory;
    private String version = "SSLv3";
    private int portnum = 1234;
    private SSLContext context;
    static  SSLHandshake client = new SSLHandshake();
    private ByteArrayOutputStream baos = new ByteArrayOutputStream();
    private InputStream bytesin;
    private InputStream inputstr;
    private OutputStream bytesout;
    private int sessionID;
    public int[] servercookie, clientcookie;
    
    
    
    PublicKey clientPubK;
    PublicKey serverPubK;
    KeyPair clientKPair;
    PrivateKey clientPrK;
    
    
    private String chosenCipherSuite;
    
    private X509Certificate serverCert, clientCert;
        private String ClientCertificateFilePath = "C:/Program Files/Java/jdk1.8.0_101/bin/sslclient.cer";
    String keyfilepath = "pks_to_pem/clientKey.key";
    static byte[] clientHelloMessage, serverhello, sCertBytes, certReq, cCertBytes, hellodone, PMS, mastersecret, hsmessages, clientverifymsg, totalhsmessages;
    
    public void Init() throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, FileNotFoundException, CertificateException, UnrecoverableKeyException{
        context = client.create_init_SSLContext(version, client.KeyStoreFilePath);
        sslsockfactory = context.getSocketFactory();
        clientsock = (SSLSocket)sslsockfactory.createSocket("127.0.0.1", portnum);
        System.out.println("Successfully connected to server at port " + portnum + ".");
        bytesin = clientsock.getInputStream();
        bytesout = clientsock.getOutputStream();
    }
    
    public void ClientSendHello(SSLSocket CS)throws NoSuchAlgorithmException, KeyManagementException, NoSuchAlgorithmException, KeyManagementException, KeyStoreException, FileNotFoundException, IOException, CertificateException, UnrecoverableKeyException {
        client.clientHello();
        sessionID = client.generateSessionID();
        System.out.println("\nSession ID: " + sessionID);
        
        String message = version + "," + sessionID + ",";
        
        clientcookie = client.clientCookie;
        for (int i = 0; i < client.clientCookie.length; i++){
            message = message + client.clientCookie[i] + " ";
        }
        message = message + ",";
        for (int i = 0; i < client.availciphersuites.length; i++){
            message += client.availciphersuites[i] + '\n';
        }
        
        System.out.println("This is the client hello message: " + message);
        clientHelloMessage = message.getBytes();
        
        bytesout.write(clientHelloMessage);
    }
    
    byte[] rcvMsg () throws IOException{
        byte[] message = new byte[10000];
        bytesin.read(message);
        return message;
    }
    
    String ConvertBytetoString(byte[] bytemessage){
        StringBuilder bye = new StringBuilder();
        for (byte b: bytemessage){
            bye.append((char)b);
        }
        return bye.toString();
    }
    
    void processServerHello(String message) throws IOException{
        //Processing each part of message split by ,
        String[] totalHello = message.split(",");
        
        //version is the first part
        String ver = totalHello[0];
        
        //session id is the second part
        int sID = Integer.parseInt(totalHello[1]);
        if (sID == sessionID){
            System.out.println("The session ID matches and is correct.");
        }
        else{
            System.out.println("Wrong session ID. Bad. Terrible.");
            clientsock.close();
        }
        
        
        //cookie (random int[]) is the third part
        String[] totalCookie = totalHello[2].split(" ");
        
        servercookie = new int[totalCookie.length];
        for (int i = 0; i < totalCookie.length; i++){
            servercookie[i] = Integer.parseInt(totalCookie[i]);
        }
        
        //available ciphersuites is the fourth and last part
        chosenCipherSuite = totalHello[3];
        
        System.out.println("Received parts of Server Hello: ");
        System.out.println("Client Version: " + ver + "\nSession ID: " + sID);
        System.out.println("Client Cookie: ");
        for (int i = 0; i < servercookie.length; i++){
            if (i == servercookie.length-1){
                System.out.printf("%d",servercookie[i]);
            }
            else
            System.out.printf("%d, ",servercookie[i]);
        }
        System.out.println("\nChosen ciphersuite: " + chosenCipherSuite);
    }
    
    X509Certificate receiveCert() throws IOException, CertificateException{
        
        serverCert = (X509Certificate) CertificateFactory.getInstance("X.509").generateCertificate(bytesin);
        sCertBytes = serverCert.getEncoded();
        System.out.println("This is the received server certificate: " + serverCert.toString());

        return serverCert;
    }
    
    void waitForHelloFinish() throws IOException{
        hellodone = new byte[30];
        bytesin.read(hellodone, 0, 30);
        String hd = ConvertBytetoString(hellodone);
        System.out.println(hd);
    }
    
    void rcvCertReq() throws IOException{
        certReq = new byte[256];
        bytesin.read(certReq, 0, 256);
        String cr = ConvertBytetoString(certReq);
        System.out.println("Received certificate request: " + cr);
    }
    
    void sendCertificate() throws CertificateException, IOException{
        
        clientCert = client.generateX509cert(ClientCertificateFilePath);
        System.out.println("This is the client certificate: " + clientCert.toString());
        cCertBytes = clientCert.getEncoded();
        bytesout.write(cCertBytes);
    }
    
    void sendPreMasterSecret() throws IOException, NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
        PMS = client.generatePreMasterSecret(serverCert);
        byte[] PMSencrypted = client.RSAencrypt(PMS, serverCert);
        bytesout.write(PMSencrypted);
    }
    
    void sendClientVerify() throws IOException, NoSuchAlgorithmException, FileNotFoundException, CertificateException, KeyStoreException, UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnrecoverableEntryException, InvalidKeySpecException {
        baos.write(clientHelloMessage);
        baos.write(serverhello);
        baos.write(sCertBytes);
        baos.write(certReq);
        baos.write(hellodone);        
        baos.write(cCertBytes);
        baos.write(PMS);
        hsmessages = baos.toByteArray();
        
        baos.reset();
        
        mastersecret = client.generateMasterSecret("Master Secret", PMS, clientcookie, servercookie);
        

        byte[] CVmd5 = client.clientVerifyHash("MD5", mastersecret, hsmessages);
        byte[] CVsha = client.clientVerifyHash("SHA-1", mastersecret, hsmessages);
        
        baos.write(CVmd5);
        baos.write(CVsha);
        
        clientverifymsg = baos.toByteArray();
        
        baos.reset();

        
        //TO DO: encrypt clientverifymsg using client's private key from client's X509Certificate and send encrypted message to server.
                readPrivateKey();
                System.out.println("Private key: " + clientPrK.toString() + clientPrK.getFormat() + clientPrK.getAlgorithm());
                clientverifymsg = privatekeyRSAencrypt(clientverifymsg, clientPrK);
                bytesout.write(clientverifymsg);
        
    }
    
    void readPrivateKey() throws FileNotFoundException, IOException, NoSuchAlgorithmException, CertificateException, KeyStoreException, UnrecoverableKeyException, UnrecoverableEntryException, InvalidKeySpecException{
        //TO DO: Generate key pair from keystore to be used in RSA asymmetric encryption/decrption for client/server verification/communication purposes.
        //loading keystore
        byte[] keybytes = Files.readAllBytes(Paths.get(keyfilepath));
        String keystring = ConvertBytetoString(keybytes);
        keystring = keystring.replace("-----BEGIN PRIVATE KEY-----", "");
        keystring = keystring.replace("-----END PRIVATE KEY-----", "");
        //keystring = keystring.replaceAll("\\s+", "");
        PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(keystring.getBytes());
        KeyFactory kf = KeyFactory.getInstance("RSA");
       clientPrK = kf.generatePrivate(keySpec);

    }
    
    byte[] privatekeyRSAencrypt(byte[] message, PrivateKey key) throws NoSuchAlgorithmException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException{
         Cipher RSACipher = Cipher.getInstance("RSA");
        RSACipher.init(ENCRYPT_MODE, key);
        return RSACipher.doFinal(message);
    }
    
    void ChangeCipherSpec() throws IOException {  
        byte message = (byte)1;
        bytesout.write(message);
    }
    
    void FinishedMessage(byte[] senderID, String cipher) throws IOException, NoSuchAlgorithmException{
        baos.write(hsmessages);
        baos.write(clientverifymsg);
        totalhsmessages = baos.toByteArray();
        baos.reset();
        
        byte[] md5hash = client.generateFinishedMsg("MD5", mastersecret, totalhsmessages, senderID);
        byte[] shahash = client.generateFinishedMsg("SHA-1", mastersecret, totalhsmessages, senderID);
        baos.write(md5hash);
        baos.write(shahash);
        byte[] finishedmsg = baos.toByteArray();
        baos.reset();
        
        byte[] encryptedfinishedmsg = encryptFinish(finishedmsg, cipher, insertkeyhere);
        
        bytesout.write(finishedmsg);
    }
    
    byte[] encryptFinish(byte[] message, String ciphertype, Key key) throws IllegalBlockSizeException, InvalidKeyException, NoSuchPaddingException, NoSuchAlgorithmException, BadPaddingException{
        Cipher ciph = Cipher.getInstance(ciphertype);
        ciph.init(ENCRYPT_MODE, key);
        return ciph.doFinal(message);
    }
    
    public static void main(String[] args) throws NoSuchAlgorithmException, KeyManagementException, KeyStoreException, IOException, FileNotFoundException, CertificateException, UnrecoverableKeyException, NoSuchPaddingException, InvalidKeyException, IllegalBlockSizeException, BadPaddingException, UnrecoverableEntryException, InvalidKeySpecException{
        HSclient hsclient = new HSclient();
        hsclient.Init();
        
        /**SSL HANDSHAKE: part 1**/
        hsclient.ClientSendHello(clientsock);
        serverhello = hsclient.rcvMsg();
        
        String sHi = hsclient.ConvertBytetoString(serverhello);
        System.out.println("Received server hello message, unprocessed: " + sHi);
        hsclient.processServerHello(sHi);
        
        /*SSL HANDSHAKE: part 2*/
        hsclient.receiveCert();
        hsclient.rcvCertReq();
        hsclient.waitForHelloFinish();
        
        /*SSL HANDSHAKE: part 3*/
        hsclient.sendCertificate();
        hsclient.sendPreMasterSecret();
        
        //TO DO: finish up sendClientVerify()
        hsclient.sendClientVerify();
        
        /*SSL HANDSHAKE: part 4*/
       String ciphertype = "DESede/CBC/PKCS5Padding";
       
        //send change_cipher_spec; message contents is a single byte, value of '1'
        hsclient.ChangeCipherSpec();
        //send finished_message = concat of two values: MD5hash size[16] and SHAhash size [20]
        //MD5(mastersecret + pad2 + SHA(hsmessages + senderid + mastersecret + pad1))
        //SHA(mastersecret + pad2 + SHA(hsmessages + senderid + mastersecret + pad1))
        hsclient.FinishedMessage("client".getBytes(), ciphertype);
        
        //receive server's change_cipher_spec message
        //receive server's finished_message
        

    }
    
}
