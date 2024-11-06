import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

public class TrabalhoAES {

    private static final int[] SBOX = {
        0x63, 0x7c, 0x77, 0x7b, 0xf0, 0x6d, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    };

    private static final int[] RCON = {
        0x01000000, // RCON[0]
        0x02000000, // RCON[1]
        0x04000000, // RCON[2]
        0x08000000, // RCON[3]
        0x10000000, // RCON[4]
        0x20000000, // RCON[5]
        0x40000000, // RCON[6]
        0x80000000, // RCON[7]
        0x1B000000, // RCON[8]
        0x36000000, // RCON[9]
        0x6C000000  // RCON[10]
    }; 

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

                byte[] textoCifrado = cifrar(gerarPadding(Files.readAllBytes(file.toPath())), chave);
                Files.write(path, textoCifrado);
                System.out.println("Pronto!");

            } else if (opcao.equalsIgnoreCase("d")) {
                File file;
                do {
                    System.out.print("Entre o caminho do arquivo que quer decifrar (a partir do diretório atual): ");
                    String caminhoDoArquivo = System.getProperty("user.dir") + scanner.next();
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
                    System.out.print("Onde guardar o arquivo decifrado (a partir do diretório atual)? ");
                    caminhoDoArquivoDecifrado = System.getProperty("user.dir") + scanner.next();
                    path = Paths.get(caminhoDoArquivoDecifrado);

                    if (!Files.exists(path)) {
                        System.out.println("ERRO: caminho não encontrado.");
                    }

                } while (!Files.exists(path));

                byte[] textoDecifrado = decifrar(Files.readAllBytes(file.toPath()), chave);
                Files.write(path, removerPadding(textoDecifrado));
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
        int[] estado = new int[16];
        for (int i = 0; i < 16; i++) {
            estado[i] = dados[i] & 0xFF;
        }

        int[] chaveExpandida = expandirChave(chave);

        estado = addRoundKey(estado, Arrays.copyOfRange(chaveExpandida, 0, 4));

        for (int round = 1; round <= 9; round++) {
            estado = subBytes(estado);
            estado = rotacionarBytes(estado);
            estado = addRoundKey(estado, Arrays.copyOfRange(chaveExpandida, round * 4, (round + 1) * 4));
        }

        estado = subBytes(estado);
        estado = rotacionarBytes(estado);
        estado = addRoundKey(estado, Arrays.copyOfRange(chaveExpandida, 40, 44));

        byte[] textoCifrado = new byte[16];
        for (int i = 0; i < 16; i++) {
            textoCifrado[i] = (byte) estado[i];
        }

        return textoCifrado;
    }

    public static byte[] decifrar(byte[] dados, String chave) throws Exception {
        int[] estado = new int[16];
        for (int i = 0; i < 16; i++) {
            estado[i] = dados[i] & 0xFF;
        }

        int[] chaveExpandida = expandirChave(chave);

        estado = addRoundKey(estado, Arrays.copyOfRange(chaveExpandida, 40, 44));
        estado = rotacionarBytes(estado);
        estado = subBytes(estado);

        for (int round = 9; round >= 1; round--) {
            estado = addRoundKey(estado, Arrays.copyOfRange(chaveExpandida, round * 4, (round + 1) * 4));
            estado = rotacionarBytes(estado);
            estado = subBytes(estado);
        }

        estado = addRoundKey(estado, Arrays.copyOfRange(chaveExpandida, 0, 4));

        byte[] textoSimples = new byte[16];
        for (int i = 0; i < 16; i++) {
            textoSimples[i] = (byte) estado[i];
        }

        return textoSimples;
    }

    private static int[] expandirChave(String chave) throws Exception {
        byte[] chaveBytes = parseChave(chave);
        int[] chaveExpandida = new int[44];

        for (int i = 0; i < 4; i++) {
            chaveExpandida[i] = ((chaveBytes[i * 4] & 0xFF) << 24) |
                                ((chaveBytes[i * 4 + 1] & 0xFF) << 16) |
                                ((chaveBytes[i * 4 + 2] & 0xFF) << 8) |
                                (chaveBytes[i * 4 + 3] & 0xFF);
        }

        for (int i = 4; i < 44; i++) {
            int temp = chaveExpandida[i - 1];
        
            if (i % 4 == 0) {
                temp = subPalavra(rotacionarPalavra(temp)) ^ RCON[i / 4 - 1];
            }
        
            chaveExpandida[i] = chaveExpandida[i - 4] ^ temp;
        }        

        return chaveExpandida;
    }

    private static int subPalavra(int palavra) {
        return (SBOX[(palavra >> 24) & 0xFF] << 24) |
               (SBOX[(palavra >> 16) & 0xFF] << 16) |
               (SBOX[(palavra >> 8) & 0xFF] << 8) |
               (SBOX[palavra & 0xFF]);
    }

    private static int rotacionarPalavra(int palavra) {
        return ((palavra << 8) & 0xFFFFFF00) | ((palavra >> 24) & 0xFF);
    }

    private static int[] addRoundKey(int[] estado, int[] roundKey) {
        for (int i = 0; i < estado.length; i++) {
            estado[i] ^= roundKey[i];
        }

        return estado;
    }

    private static int[] subBytes(int[] estado) {
        for (int i = 0; i < estado.length; i++) {
            estado[i] = SBOX[estado[i] & 0xFF];
        }

        return estado;
    }

    private static int[] rotacionarBytes(int[] estado) {
        int[] novoEstado = new int[16];
        for (int i = 0; i < 16; i++) {
            novoEstado[i] = estado[(i + 1) % 16];
        }

        return novoEstado;
    }

    private static byte[] gerarPadding(byte[] dados) {
        int padding = 16 - (dados.length % 16);
        byte[] resultado = new byte[dados.length + padding];
        System.arraycopy(dados, 0, resultado, 0, dados.length);

        for (int i = dados.length; i < resultado.length; i++) {
            resultado[i] = (byte) padding;
        }

        return resultado;
    }

    private static byte[] removerPadding(byte[] dados) {
        int padding = dados[dados.length - 1];
        byte[] resultado = new byte[dados.length - padding];
        System.arraycopy(dados, 0, resultado, 0, dados.length - padding);

        return resultado;
    }

    public static String gerarChaveAleatoria() {
        SecureRandom rand = new SecureRandom();
        StringBuilder chave = new StringBuilder();

        for (int i = 0; i < 16; i++) {
            if (i > 0) chave.append(",");
            chave.append(rand.nextInt(256));
        }

        return chave.toString();
    }

    public static byte[] parseChave(String chave) throws Exception {
        String[] strings = chave.split(",");

        if (strings.length != 16) {
            throw new Exception("A chave deve conter 16 bytes.");
        }

        byte[] chaveBytes = new byte[16];
        for (int i = 0; i < 16; i++) {
            chaveBytes[i] = (byte) Integer.parseInt(strings[i].trim());
        }

        return chaveBytes;
    }
}
