import javax.crypto.*;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.File;
import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.util.Base64;

public class Aes {
    public static SecretKey generateKey(int n) throws NoSuchAlgorithmException {
        KeyGenerator keyGenerator = KeyGenerator.getInstance("AES");
        keyGenerator.init(n);
        return keyGenerator.generateKey();
    }
    public static String convertSecretKeyToString(SecretKey secretKey) {
        byte[] rawData = secretKey.getEncoded();
        return Base64.getEncoder().encodeToString(rawData);
    }
    public static SecretKey keyDecry(String encodedKey) {
        byte[] decodedKey = Base64.getDecoder().decode(encodedKey);
        return new SecretKeySpec(decodedKey, 0, decodedKey.length, "AES");
    }




    public static IvParameterSpec generateIv() {
        byte[] iv = new byte[16];
        new SecureRandom().nextBytes(iv);
        return new IvParameterSpec(iv);
    }

    public static String encrypt(String algorithm, String input, SecretKey key, IvParameterSpec iv)
            throws NoSuchPaddingException, NoSuchAlgorithmException, InvalidAlgorithmParameterException,
            InvalidKeyException, BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        byte[] cipherText = cipher.doFinal(input.getBytes());
        return Base64.getEncoder()
                .encodeToString(cipherText);
    }

    public static String decrypt(String algorithm, String cipherText, SecretKey key,
                                 IvParameterSpec iv) throws NoSuchPaddingException, NoSuchAlgorithmException,
            InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {

        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        byte[] plainText = cipher.doFinal(Base64.getDecoder()
                .decode(cipherText));
        return new String(plainText);
    }


    public static void encryptFile(String algorithm, SecretKey key, IvParameterSpec iv,
                                   File inputFile, File outputFile) throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.ENCRYPT_MODE, key, iv);
        FileInputStream inputStream = new FileInputStream(inputFile);
        FileOutputStream outputStream = new FileOutputStream(outputFile);
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] outputBytes = cipher.doFinal();
        if (outputBytes != null) {
            outputStream.write(outputBytes);
        }
        inputStream.close();
        outputStream.close();
    }

    public static void decryptFile(String algorithm, SecretKey key, IvParameterSpec iv,
                                   File encryptedFile, File decryptedFile) throws IOException, NoSuchPaddingException,
            NoSuchAlgorithmException, InvalidAlgorithmParameterException, InvalidKeyException,
            BadPaddingException, IllegalBlockSizeException {
        Cipher cipher = Cipher.getInstance(algorithm);
        cipher.init(Cipher.DECRYPT_MODE, key, iv);
        FileInputStream inputStream = new FileInputStream(encryptedFile);
        FileOutputStream outputStream = new FileOutputStream(decryptedFile);
        byte[] buffer = new byte[64];
        int bytesRead;
        while ((bytesRead = inputStream.read(buffer)) != -1) {
            byte[] output = cipher.update(buffer, 0, bytesRead);
            if (output != null) {
                outputStream.write(output);
            }
        }
        byte[] output = cipher.doFinal();
        if (output != null) {
            outputStream.write(output);
        }
        inputStream.close();
        outputStream.close();
    }


    public static void main(String[] args) throws NoSuchAlgorithmException, InvalidAlgorithmParameterException, NoSuchPaddingException, IllegalBlockSizeException, IOException, BadPaddingException, InvalidKeyException {
        SecretKey key = generateKey(256);
        IvParameterSpec ivParameterSpec = Aes.generateIv();
        String strKey = convertSecretKeyToString(key);
        System.out.println("key of sender to be encrypted : "+strKey);

        String RstrKey = RSA.rsaKey();
        SecretKey decryptedKey = keyDecry(RstrKey);
        System.out.println("decrypted key at receiver : "+convertSecretKeyToString(decryptedKey));
        String algorithm = "AES/CBC/PKCS5Padding";
        String cipher = encrypt(algorithm,"Hello! ",decryptedKey,ivParameterSpec);
        System.out.println("Encrypted message : "+cipher);

        String plainText = decrypt(algorithm,cipher,decryptedKey,ivParameterSpec);
        System.out.println("decrypted message : "+plainText);


        File inputFile = Paths.get("src/resources/shch.jpg")
                .toFile();
        File encryptedFile = new File("classpaths:AES.encrypted");
        File decryptedFile = new File("document5.jpg");
        Aes.encryptFile(algorithm, decryptedKey, ivParameterSpec, inputFile, encryptedFile);
        Aes.decryptFile(algorithm, decryptedKey, ivParameterSpec, encryptedFile, decryptedFile);

        File inputFile1 = Paths.get("src/resources/video.mp4")
                .toFile();
        File encryptedFile1 = new File("classpath1:AES.encrypted");
        File decryptedFile1 = new File("document1.mp4");
        Aes.encryptFile(algorithm, decryptedKey, ivParameterSpec, inputFile1, encryptedFile1);
        Aes.decryptFile(algorithm, decryptedKey, ivParameterSpec, encryptedFile1, decryptedFile1);

        File inputFile2 = Paths.get("src/resources/text.txt")
                .toFile();
        File encryptedFile2 = new File("classpath2:AES.encrypted");
        File decryptedFile2 = new File("document2.txt");
        Aes.encryptFile(algorithm, decryptedKey, ivParameterSpec, inputFile2, encryptedFile2);
        Aes.decryptFile(algorithm, decryptedKey, ivParameterSpec, encryptedFile2, decryptedFile2);

        File inputFile3 = Paths.get("src/resources/Image encryption using aes`.pptx")
                .toFile();
        File encryptedFile3 = new File("classpath3:AES.encrypted");
        File decryptedFile3 = new File("document3.pptx");
        Aes.encryptFile(algorithm, decryptedKey, ivParameterSpec, inputFile3, encryptedFile3);
        Aes.decryptFile(algorithm, decryptedKey, ivParameterSpec, encryptedFile3, decryptedFile3);

        File inputFile4 = Paths.get("src/resources/JAVA PROGRAMMING.docx")
                .toFile();
        File encryptedFile4 = new File("classpath4:AES.encrypted");
        File decryptedFile4 = new File("document4.docx");
        Aes.encryptFile(algorithm, decryptedKey, ivParameterSpec, inputFile4, encryptedFile4);
        Aes.decryptFile(algorithm, decryptedKey, ivParameterSpec, encryptedFile4, decryptedFile4);

        File inputFile5 = Paths.get("src/resources/res.pdf")
                .toFile();
        File encryptedFile5 = new File("classpath3:AES.encrypted");
        File decryptedFile5 = new File("document5.pdf");
        Aes.encryptFile(algorithm, decryptedKey, ivParameterSpec, inputFile5, encryptedFile5);
        Aes.decryptFile(algorithm, decryptedKey, ivParameterSpec, encryptedFile5, decryptedFile5);

        File inputFile6 = Paths.get("src/resources/bvrit2.xlsx")
                .toFile();
        File encryptedFile6 = new File("classpath6:AES.encrypted");
        File decryptedFile6 = new File("document6.xlsx");
        Aes.encryptFile(algorithm, decryptedKey, ivParameterSpec, inputFile6, encryptedFile6);
        Aes.decryptFile(algorithm, decryptedKey, ivParameterSpec, encryptedFile6, decryptedFile6);

        File inputFile7 = Paths.get("src/resources/Be_kind_.mp3")
                .toFile();
        File encryptedFile7 = new File("classpath7:AES.encrypted");
        File decryptedFile7 = new File("document7.mp3");
        Aes.encryptFile(algorithm, decryptedKey, ivParameterSpec, inputFile7, encryptedFile7);
        Aes.decryptFile(algorithm, decryptedKey, ivParameterSpec, encryptedFile7, decryptedFile7);

        File inputFile8 = Paths.get("src/resources/My Trove.apk")
                .toFile();
        File encryptedFile8 = new File("classpath8:AES.encrypted");
        File decryptedFile8 = new File("document8.apk");
        Aes.encryptFile(algorithm, decryptedKey, ivParameterSpec, inputFile8, encryptedFile8);
        Aes.decryptFile(algorithm, decryptedKey, ivParameterSpec, encryptedFile8, decryptedFile8);
    }
}