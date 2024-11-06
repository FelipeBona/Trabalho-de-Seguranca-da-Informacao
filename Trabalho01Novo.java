import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

public class Trabalho01Novo {
    
    private static final int[] SBOX = {
        0x63, 0x7c, 0x77, 0x7b, 0xf0, 0x6d, 0x6b, 0x6f, 0xc5, 0x30, 0x01, 0x67, 0x2b, 0xfe, 0xd7, 0xab, 0x76,
    };
    
    private static final int[] RCON = {
        0x01000000, 0x02000000, 0x04000000, 0x08000000, 0x10000000, 0x20000000, 0x40000000, 0x80000000, 0x1b000000, 0x36000000
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

                byte[] textoCifrado = cifrar(addPadding(Files.readAllBytes(file.toPath())), chave);
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
                Files.write(path, removePadding(textoDecifrado));
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
            estado = misturarColunas(estado);
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
            estado = misturarColunas(estado);
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
                temp = subWord
        (rotpalavra(temp)) ^ RCON[i / 4 - 1];
            }

            chaveExpandida[i] = chaveExpandida[i - 4] ^ temp;
        }

        return chaveExpandida;
    }

    private static int subWord(int palavra) {
        return (SBOX[(palavra >> 24) & 0xFF] << 24) |
               (SBOX[(palavra >> 16) & 0xFF] << 16) |
               (SBOX[(palavra >> 8) & 0xFF] << 8) |
               (SBOX[palavra & 0xFF]);
    }

    private static int rotpalavra(int palavra) {
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
        int temp = estado[1];
        estado[1] = estado[5];
        estado[5] = estado[9];
        estado[9] = estado[13];
        estado[13] = temp;
        return estado;
    }

    private static int[] misturarColunas(int[] estado) {
        return estado;
    }

    public static byte[] parseChave(String chave) throws Exception {
        String[] strings = chave.split(",");
        if (strings.length != 16) throw new Exception("A chave deve conter 16 bytes.");
        byte[] chaveBytes = new byte[16];

        for (int i = 0; i < 16; i++) {
            chaveBytes[i] = (byte) Integer.parseInt(strings[i].trim());
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

    private static byte[] addPadding(byte[] dados) {
        int tamanhoOriginal = dados.length;
        int padding = 16 - (tamanhoOriginal % 16);
        byte[] dadosComPadding = new byte[tamanhoOriginal + padding];
        System.arraycopy(dados, 0, dadosComPadding, 0, tamanhoOriginal);

        for (int i = tamanhoOriginal; i < dadosComPadding.length; i++) {
            dadosComPadding[i] = (byte) padding;
        }

        return dadosComPadding;
    }

    private static byte[] removePadding(byte[] dados) {
        int padding = dados[dados.length - 1];
        return Arrays.copyOf(dados, dados.length - padding);
    }
}
