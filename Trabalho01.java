import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Scanner;
import javax.crypto.Cipher;
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

            if (opcao.equalsIgnoreCase("c")) {
                File file;

                do {
                    System.out.print("Entre o caminho do arquivo que quer cifrar (a partir do diretório atual): ");
                    String caminhoDoArquivo = System.getProperty("user.dir") + scanner.next();
                    file = new File(caminhoDoArquivo);

                    if (!file.exists()) {
                        System.out.println("ERRO: arquivo não encontrado.");
                    }

                } while (!file.exists());

                System.out.print("Forneça a chave ou tecle G para gerar uma: ");
                String chave = scanner.next();

                if (chave.equalsIgnoreCase("g")) {
                    chave = gerarChaveAleatoria();
                    System.out.println("A sua chave é: " + chave + ". Anote-a para não esquecer.");
                }

                Path path;
                String caminhoDoArquivoCifrado;

                do {
                    System.out.print("Onde guardar o arquivo cifrado (a partir do diretório atual)? ");
                    caminhoDoArquivoCifrado = System.getProperty("user.dir") + scanner.next();
                    path = Paths.get(caminhoDoArquivoCifrado);

                    if (!Files.exists(path)) {
                        System.out.println("ERRO: caminho não encontrado.");
                    }

                } while (!Files.exists(path));

                byte[] textoCifrado = cifrar(Files.readAllBytes(file.toPath()), chave);
                Files.write(path, textoCifrado);
                System.out.println("Pronto!");

            } else if (opcao.equalsIgnoreCase("d")) {
                File file;
                do {
                    System.out.print("Entre o caminho do arquivo que quer decifrar (a partir do diretório atual): ");
                    String caminhoDoArquivo = scanner.next();
                    file = new File(caminhoDoArquivo);

                    if (!file.exists()) {
                        System.out.println("ERRO: arquivo não encontrado.");
                    }

                } while (!file.exists());

                System.out.print("Forneça a chave: ");
                String chave = scanner.next();

                Path path;
                String caminhoDoArquivoDecifrado;

                do {
                    System.out.print("Onde guardar o arquivo cifrado (a partir do diretório atual)? ");
                    caminhoDoArquivoDecifrado = System.getProperty("user.dir") + scanner.next();
                    path = Paths.get(caminhoDoArquivoDecifrado);

                    if (!Files.exists(path)) {
                        System.out.println("ERRO: caminho não encontrado.");
                    }

                } while (!Files.exists(path));

                byte[] textoDecifrado = decifrar(Files.readAllBytes(file.toPath()), chave);
                Files.write(path, textoDecifrado);
                System.out.println("Pronto!");

            } else if (opcao.equalsIgnoreCase("s")) {
                loop = false;

            } else {
                System.out.println("ERRO: opção inválida.");
            }
        }

        scanner.close();

    }

    public static byte[] cifrar(byte[] dados, String chave) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMACAO);
        SecretKeySpec secretKeySpec = new SecretKeySpec(parseChave(chave), ALGORITMO);
        cipher.init(Cipher.ENCRYPT_MODE, secretKeySpec);

        return cipher.doFinal(dados);

    }

    public static byte[] decifrar(byte[] dados, String chave) throws Exception {
        Cipher cipher = Cipher.getInstance(TRANSFORMACAO);
        SecretKeySpec secretKeySpec = new SecretKeySpec(parseChave(chave), ALGORITMO);
        cipher.init(Cipher.DECRYPT_MODE, secretKeySpec);

        return cipher.doFinal(dados);

    }

    public static byte[] parseChave(String chave) throws Exception {
        String[] byteValues = chave.split(",");
        if (byteValues.length != 16) throw new Exception("A chave deve conter 16 bytes.");
        byte[] chaveBytes = new byte[16];

        for (int i = 0; i < 16; i++) {
            chaveBytes[i] = (byte) Integer.parseInt(byteValues[i].trim());
        }

        return chaveBytes;
        
    }

    public static String gerarChaveAleatoria() {
        SecureRandom secureRandom = new SecureRandom();
        byte[] chave = new byte[16];
        secureRandom.nextBytes(chave);
        StringBuilder chaveFormatada = new StringBuilder();

        for (int i = 0; i < chave.length; i++) {
            chaveFormatada.append(chave[i] & 0xff);
            if (i < chave.length - 1) chaveFormatada.append(",");
        }

        return chaveFormatada.toString();

    }
}
