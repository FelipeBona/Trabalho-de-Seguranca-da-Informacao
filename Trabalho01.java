import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidAlgorithmParameterException;
import java.security.SecureRandom;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Trabalho01 {

    private static final String ALGORITMO = "AES";
    private static final String TRANSFORMACAO = "AES/ECB/PKCS5Padding";
    public static void main(String[] args) throws Exception {
        boolean loop = true;
        Scanner scanner = new Scanner(System.in);

        while (loop) {

            System.out.print("Quer cifrar (C) ou decifrar (D)? S para sair: ");
            String opcao = scanner.next();

            if (opcao.toLowerCase().equals("c")) {
                boolean arquivoExiste = true;
                File file;
                
                do {             
                    System.out.print("Entre o caminho do arquivo que quer cifrar: ");            
                    String caminhoDoArquivo = scanner.next();
                    file = new File(caminhoDoArquivo);
    
                    if (file.exists()) {
                        arquivoExiste = true;
                    } else {
                        System.out.println("ERRO: arquivo não encontrado.");
                        arquivoExiste = false;                       
                    }

                } while (!arquivoExiste);

                System.out.print("Forneça a chave ou tecle G para gerar uma: ");
                String chave = scanner.next();

                if (chave.toLowerCase().equals("g")) {
                    chave = gerarChaveAleatoria();
                    System.out.println("A sua chave é " + chave + ". Anote-a para não esquecer.");
                }

                String textoCifrado;
                Path path;

                try {
                    textoCifrado = cifrar(file.toString(), chave);
                    arquivoExiste = true;
                } catch (InvalidAlgorithmParameterException e) {
                    throw new Exception("ERRO: a chave deve conter 16 bytes.");
                }

                do {             
                    System.out.print("Onde guardar o arquivo cifrado? ");            
                    String caminhoDoArquivo = scanner.next();
                    path = Paths.get(caminhoDoArquivo);

                    if (Files.exists(path)) {
                        arquivoExiste = true;
                    } else {
                        System.out.println("ERRO: caminho não encontrado.");
                        arquivoExiste = false;                       
                    }

                } while (!arquivoExiste);

                try {
                    Files.write(path, textoCifrado.getBytes());
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                }

                System.out.println("Pronto!");

            } else if (opcao.toLowerCase().equals("d")) {
                boolean arquivoExiste = true;
                File file;
                
                do {             
                    System.out.print("Entre o caminho do arquivo que quer decifrar: ");            
                    String caminhoDoArquivo = scanner.next();
                    file = new File(caminhoDoArquivo);
    
                    if (file.exists()) {
                        arquivoExiste = true;
                    } else {
                        System.out.println("ERRO: arquivo não encontrado.");
                        arquivoExiste = false;                       
                    }

                } while (!arquivoExiste);

                System.out.print("Forneça a chave:");
                String chave = scanner.next();
                String textoDecifrado;
                Path path;

                try {
                    textoDecifrado = decifrar(file.toString(), chave);
                    arquivoExiste = true;
                } catch (InvalidAlgorithmParameterException e) {
                    throw new Exception("ERRO: a chave deve conter 16 bytes.");
                }
                
                arquivoExiste = true;

                do {             
                    System.out.print("Onde guardar o arquivo decifrado? ");            
                    String caminhoDoArquivo = scanner.next();
                    path = Paths.get(caminhoDoArquivo);
    
                    if (!Files.exists(path)) {
                        System.out.println("ERRO: caminho não encontrado.");
                        arquivoExiste = false;
                    } else {
                        arquivoExiste = true;
                    }

                } while (!arquivoExiste);

                try {
                    Files.write(path, textoDecifrado.getBytes());
                } catch (IOException e) {
                    System.out.println(e.getMessage());
                }

                System.out.println("Pronto!");

            } else if (opcao.toLowerCase().equals("s")) {
                loop = false;

            } else {
                System.out.println("ERRO: opção inválida.");

            }

        } 

        scanner.close();

    }

    public static String cifrar(String texto, String chave) throws Exception {       
        Cipher cipher = Cipher.getInstance(TRANSFORMACAO);
        SecretKeySpec secretKeySpec = new SecretKeySpec(chave.getBytes(), ALGORITMO);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(chave.getBytes());
        
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] bytesCifrados = cipher.doFinal(texto.getBytes());

        return Base64.getEncoder().encodeToString(bytesCifrados);

    }

    public static String decifrar(String texto, String chave) throws Exception {         
        Cipher cipher = Cipher.getInstance(TRANSFORMACAO);
        SecretKeySpec secretKeySpec = new SecretKeySpec(chave.getBytes(), ALGORITMO);
        IvParameterSpec ivParameterSpec = new IvParameterSpec(chave.getBytes());

        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec, ivParameterSpec);
        byte[] bytesDecifrados = cipher.doFinal(Base64.getDecoder().decode(texto));

        return new String(bytesDecifrados);

    }


    public static String gerarChaveAleatoria() {        
        SecureRandom secureRandom = new SecureRandom();
        byte[] chave = new byte[16];
        secureRandom.nextBytes(chave);

        StringBuilder hexString = new StringBuilder();
        for (byte b : chave) {
            String hex = Integer.toHexString(0xff & b);
            if (hex.length() == 1) hexString.append('0');
            hexString.append(hex);
        }

        return hexString.toString();

    }

}