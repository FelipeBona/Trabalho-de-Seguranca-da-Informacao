import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

public class Trabalho01 {
    
    private static final int[] SBOX = {
        0x63, 0x7C, 0x77, 0x7B, 0xF2, 0x6B, 0x6F, 0xC5, 0x30, 0x01, 0x67, 0x2B, 0xFE, 0xD7, 0xAB, 0x76,
        0xCA, 0x82, 0xC9, 0x7D, 0xFA, 0x59, 0x47, 0xF0, 0xAD, 0xD4, 0xA2, 0xAF, 0x9C, 0xA4, 0x72, 0xC0,
        0xB7, 0xFD, 0x93, 0x26, 0x36, 0x3F, 0xF7, 0xCC, 0x34, 0xA5, 0xE5, 0xF1, 0x71, 0xD8, 0x31, 0x15,
        0x04, 0xC7, 0x23, 0xC3, 0x18, 0x96, 0x05, 0x9A, 0x07, 0x12, 0x80, 0xE2, 0xEB, 0x27, 0xB2, 0x75,
        0x09, 0x83, 0x2C, 0x1A, 0x1B, 0x6E, 0x5A, 0xA0, 0x52, 0x3B, 0xD6, 0xB3, 0x29, 0xE3, 0x2F, 0x84,
        0x53, 0xD1, 0x00, 0xED, 0x20, 0xFC, 0xB1, 0x5B, 0x6A, 0xCB, 0xBE, 0x39, 0x4A, 0x4C, 0x58, 0xCF,
        0xD0, 0xEF, 0xAA, 0xFB, 0x43, 0x4D, 0x33, 0x85, 0x45, 0xF9, 0x02, 0x7F, 0x50, 0x3C, 0x9F, 0xA8,
        0x51, 0xA3, 0x40, 0x8F, 0x92, 0x9D, 0x38, 0xF5, 0xBC, 0xB6, 0xDA, 0x21, 0x10, 0xFF, 0xF3, 0xD2,
        0xCD, 0x0C, 0x13, 0xEC, 0x5F, 0x97, 0x44, 0x17, 0xC4, 0xA7, 0x7E, 0x3D, 0x64, 0x5D, 0x19, 0x73,
        0x60, 0x81, 0x4F, 0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB,
        0xE0, 0x32, 0x3A, 0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79,
        0xE7, 0xC8, 0x37, 0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08,
        0xBA, 0x78, 0x25, 0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A,
        0x70, 0x3E, 0xB5, 0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E,
        0xE1, 0xF8, 0x98, 0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF,
        0x8C, 0xA1, 0x89, 0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
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
                File file = getFile(scanner, "Entre o caminho do arquivo que quer cifrar (a partir do diretório atual): ");
                
                System.out.print("Forneça a chave ou tecle G para gerar uma: ");
                String chave = scanner.next();
                
                if (chave.equalsIgnoreCase("g")) {
                    chave = gerarChaveAleatoria();
                    System.out.println("A sua chave é: " + chave + ". Anote-a para não esquecer.");
                }

                Path path = getPath(scanner, "Onde guardar o arquivo cifrado (a partir do diretório atual): ");

                byte[] textoCifrado = cifrar(addPadding(Files.readAllBytes(file.toPath())), chave);
                Files.write(path, textoCifrado);
                System.out.println("Pronto!");

            } else if (opcao.equalsIgnoreCase("d")) {
                File file = getFile(scanner, "Entre o caminho do arquivo que quer decifrar (a partir do diretório atual): ");
                
                System.out.print("Forneça a chave: ");
                String chave = scanner.next();

                Path path = getPath(scanner, "Onde guardar o arquivo decifrado (a partir do diretório atual): ");

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

    private static File getFile(Scanner scanner, String mensagem) {
        File file;
        do {
            System.out.print(mensagem);
            String caminhoDoArquivo = System.getProperty("user.dir") + "/" + scanner.next();
            file = new File(caminhoDoArquivo);
            if (!file.exists()) {
                System.out.println("ERRO: arquivo não encontrado.");
            }
        } while (!file.exists());
        return file;
    }

    private static Path getPath(Scanner scanner, String mensagem) {
        Path path;
        do {
            System.out.print(mensagem);
            String caminhoDoArquivo = System.getProperty("user.dir") + "/" + scanner.next();
            path = Paths.get(caminhoDoArquivo);
        } while (!Files.isWritable(path.getParent()));
        return path;
    }

    public static byte[] cifrar(byte[] dados, String chave) throws Exception {
        int[] estado = new int[16];
        for (int i = 0; i < 16; i++) {
            estado[i] = dados[i] & 0xFF;
        }

        int[] chaveExpandida = expandirChave(chave);

        // Aplica a primeira chave expandida
        estado = addRoundKey(estado, Arrays.copyOfRange(chaveExpandida, 0, 16));

        // Realiza as 9 rodadas de criptografia
        for (int round = 1; round <= 9; round++) {
            estado = subBytes(estado);
            estado = rotacionarBytes(estado);
            estado = misturarColunas(estado);
            estado = addRoundKey(estado, Arrays.copyOfRange(chaveExpandida, round * 16, (round + 1) * 16));
        }

        // Rodada final
        estado = subBytes(estado);
        estado = rotacionarBytes(estado);
        estado = addRoundKey(estado, Arrays.copyOfRange(chaveExpandida, 160, 176));

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
   
        estado = addRoundKey(estado, Arrays.copyOfRange(chaveExpandida, 160, 176)); 
        estado = rotacionarBytes(estado);  
        estado = invSubBytes(estado);     
   
        for (int round = 9; round >= 1; round--) {
            estado = addRoundKey(estado, Arrays.copyOfRange(chaveExpandida, round * 16, (round + 1) * 16)); 
            estado = invMixColumns(estado);   
            estado = rotacionarBytes(estado);
            estado = invSubBytes(estado);   
        }
   
        estado = addRoundKey(estado, Arrays.copyOfRange(chaveExpandida, 0, 16)); 
   
        byte[] textoSimples = new byte[16];
        for (int i = 0; i < 16; i++) {
            textoSimples[i] = (byte) estado[i];
        }
   
        return textoSimples;
    }
   

    private static int[] expandirChave(String chave) throws Exception {
        byte[] chaveBytes = parseChave(chave);
        int[] chaveExpandida = new int[176];

        for (int i = 0; i < 4; i++) {
            chaveExpandida[i] = ((chaveBytes[i * 4] & 0xFF) << 24) |
                             ((chaveBytes[i * 4 + 1] & 0xFF) << 16) |
                             ((chaveBytes[i * 4 + 2] & 0xFF) << 8) |
                             (chaveBytes[i * 4 + 3] & 0xFF);
        }

        for (int i = 4; i < 44; i++) {
            int temp = chaveExpandida[i - 1];
            if (i % 4 == 0) {
                temp = subWord(rotpalavra(temp)) ^ RCON[i / 4 - 1];
            }
            chaveExpandida[i] = chaveExpandida[i - 4] ^ temp;
        }

        int[] chaveExpandidaFinal = new int[176];
        for (int i = 0; i < 44; i++) {
            int palavra = chaveExpandida[i];
            chaveExpandidaFinal[i * 4] = (palavra >> 24) & 0xFF;
            chaveExpandidaFinal[i * 4 + 1] = (palavra >> 16) & 0xFF;
            chaveExpandidaFinal[i * 4 + 2] = (palavra >> 8) & 0xFF;
            chaveExpandidaFinal[i * 4 + 3] = palavra & 0xFF;
        }
        return chaveExpandidaFinal;
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

        temp = estado[2];
        estado[2] = estado[10];
        estado[10] = temp;
        temp = estado[6];
        estado[6] = estado[14];
        estado[14] = temp;

        temp = estado[3];
        estado[3] = estado[15];
        estado[15] = estado[11];
        estado[11] = estado[7];
        estado[7] = temp;
        
        return estado;
    }

    private static int[] misturarColunas(int[] estado) {
        int[] resultado = new int[16];
        for (int i = 0; i < 4; i++) {
            int a = estado[i];
            int b = estado[4 + i];
            int c = estado[8 + i];
            int d = estado[12 + i];

            resultado[i] = galoisMult(a, 2) ^ galoisMult(b, 3) ^ c ^ d;
            resultado[4 + i] = a ^ galoisMult(b, 2) ^ galoisMult(c, 3) ^ d;
            resultado[8 + i] = a ^ b ^ galoisMult(c, 2) ^ galoisMult(d, 3);
            resultado[12 + i] = galoisMult(a, 3) ^ b ^ c ^ galoisMult(d, 2);
        }
        return resultado;
    }

    private static int galoisMult(int a, int b) {
        int p = 0;
        int hiBitSet;
        for (int i = 0; i < 8; i++) {
            if ((b & 1) != 0) {
                p ^= a;
            }
            hiBitSet = a & 0x80;
            a <<= 1;
            if (hiBitSet != 0) {
                a ^= 0x1b;
            }
            b >>= 1;
        }
        return p & 0xFF;
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

    private static int[] invSubBytes(int[] estado) {
        for (int i = 0; i < estado.length; i++) {
            estado[i] = SBOX_INV[estado[i] & 0xFF];
        }
        return estado;
    }
    
    private static int[] invShiftRows(int[] estado) {
        int[] temp = estado.clone();
        temp[1] = estado[5];
        temp[5] = estado[9];
        temp[9] = estado[13];
        temp[13] = estado[1];
    
        temp[2] = estado[10];
        temp[6] = estado[14];
        temp[10] = estado[2];
        temp[14] = estado[6];
    
        temp[3] = estado[15];
        temp[7] = estado[11];
        temp[11] = estado[7];
        temp[15] = estado[3];
    
        return temp;
    }
    
    private static int[] invMixColumns(int[] estado) {
        int[] resultado = new int[16];
        for (int i = 0; i < 4; i++) {
            int a = estado[i];
            int b = estado[4 + i];
            int c = estado[8 + i];
            int d = estado[12 + i];
    
            resultado[i] = galoisMult(a, 14) ^ galoisMult(b, 11) ^ galoisMult(c, 13) ^ galoisMult(d, 9);
            resultado[4 + i] = galoisMult(a, 9) ^ galoisMult(b, 14) ^ galoisMult(c, 11) ^ galoisMult(d, 13);
            resultado[8 + i] = galoisMult(a, 13) ^ galoisMult(b, 9) ^ galoisMult(c, 14) ^ galoisMult(d, 11);
            resultado[12 + i] = galoisMult(a, 11) ^ galoisMult(b, 13) ^ galoisMult(c, 9) ^ galoisMult(d, 14);
        }
        return resultado;
    }
    
    private static final int[] SBOX_INV = {
        0x52, 0x09, 0x6A, 0xD5, 0x30, 0x36, 0xA5, 0x38, 0xBF, 0x40, 0xA3, 0x9E, 0x81, 0xF3, 0xD7, 0xFB,
        0x7C, 0x7B, 0xF2, 0xC3, 0x2C, 0x9B, 0x7F, 0x8C, 0x3D, 0x64, 0x5D, 0x19, 0x73, 0x60, 0x81, 0x4F,
        0xDC, 0x22, 0x2A, 0x90, 0x88, 0x46, 0xEE, 0xB8, 0x14, 0xDE, 0x5E, 0x0B, 0xDB, 0xE0, 0x32, 0x3A,
        0x0A, 0x49, 0x06, 0x24, 0x5C, 0xC2, 0xD3, 0xAC, 0x62, 0x91, 0x95, 0xE4, 0x79, 0xE7, 0xC8, 0x37,
        0x6D, 0x8D, 0xD5, 0x4E, 0xA9, 0x6C, 0x56, 0xF4, 0xEA, 0x65, 0x7A, 0xAE, 0x08, 0xBA, 0x78, 0x25,
        0x2E, 0x1C, 0xA6, 0xB4, 0xC6, 0xE8, 0xDD, 0x74, 0x1F, 0x4B, 0xBD, 0x8B, 0x8A, 0x70, 0x3E, 0xB5,
        0x66, 0x48, 0x03, 0xF6, 0x0E, 0x61, 0x35, 0x57, 0xB9, 0x86, 0xC1, 0x1D, 0x9E, 0xE1, 0xF8, 0x98,
        0x11, 0x69, 0xD9, 0x8E, 0x94, 0x9B, 0x1E, 0x87, 0xE9, 0xCE, 0x55, 0x28, 0xDF, 0x8C, 0xA1, 0x89,
        0x0D, 0xBF, 0xE6, 0x42, 0x68, 0x41, 0x99, 0x2D, 0x0F, 0xB0, 0x54, 0xBB, 0x16
    };
    
}
