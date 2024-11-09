import java.io.File;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.SecureRandom;
import java.util.Arrays;
import java.util.Scanner;

public class AES {

    private final static byte[][] SBOX = {
            { (byte) 0x63, (byte) 0x7C, (byte) 0x77, (byte) 0x7B, (byte) 0xF2, (byte) 0x6B, (byte) 0x6F, (byte) 0xC5, (byte) 0x30, (byte) 0x01, (byte) 0x67, (byte) 0x2B,
                    (byte) 0xFE, (byte) 0xD7, (byte) 0xAB, (byte) 0x76 },
            { (byte) 0xCA, (byte) 0x82, (byte) 0xC9, (byte) 0x7D, (byte) 0xFA, (byte) 0x59, (byte) 0x47, (byte) 0xF0, (byte) 0xAD, (byte) 0xD4, (byte) 0xA2, (byte) 0xAF,
                    (byte) 0x9C, (byte) 0xA4, (byte) 0x72, (byte) 0xC0 },
            { (byte) 0xB7, (byte) 0xFD, (byte) 0x93, (byte) 0x26, (byte) 0x36, (byte) 0x3F, (byte) 0xF7, (byte) 0xCC, (byte) 0x34, (byte) 0xA5, (byte) 0xE5, (byte) 0xF1,
                    (byte) 0x71, (byte) 0xD8, (byte) 0x31, (byte) 0x15 },
            { (byte) 0x04, (byte) 0xC7, (byte) 0x23, (byte) 0xC3, (byte) 0x18, (byte) 0x96, (byte) 0x05, (byte) 0x9A, (byte) 0x07, (byte) 0x12, (byte) 0x80, (byte) 0xE2,
                    (byte) 0xEB, (byte) 0x27, (byte) 0xB2, (byte) 0x75 },
            { (byte) 0x09, (byte) 0x83, (byte) 0x2C, (byte) 0x1A, (byte) 0x1B, (byte) 0x6E, (byte) 0x5A, (byte) 0xA0, (byte) 0x52, (byte) 0x3B, (byte) 0xD6, (byte) 0xB3,
                    (byte) 0x29, (byte) 0xE3, (byte) 0x2F, (byte) 0x84 },
            { (byte) 0x53, (byte) 0xD1, (byte) 0x00, (byte) 0xED, (byte) 0x20, (byte) 0xFC, (byte) 0xB1, (byte) 0x5B, (byte) 0x6A, (byte) 0xCB, (byte) 0xBE, (byte) 0x39,
                    (byte) 0x4A, (byte) 0x4C, (byte) 0x58, (byte) 0xCF },
            { (byte) 0xD0, (byte) 0xEF, (byte) 0xAA, (byte) 0xFB, (byte) 0x43, (byte) 0x4D, (byte) 0x33, (byte) 0x85, (byte) 0x45, (byte) 0xF9, (byte) 0x02, (byte) 0x7F,
                    (byte) 0x50, (byte) 0x3C, (byte) 0x9F, (byte) 0xA8 },
            { (byte) 0x51, (byte) 0xA3, (byte) 0x40, (byte) 0x8F, (byte) 0x92, (byte) 0x9D, (byte) 0x38, (byte) 0xF5, (byte) 0xBC, (byte) 0xB6, (byte) 0xDA, (byte) 0x21,
                    (byte) 0x10, (byte) 0xFF, (byte) 0xF3, (byte) 0xD2 },
            { (byte) 0xCD, (byte) 0x0C, (byte) 0x13, (byte) 0xEC, (byte) 0x5F, (byte) 0x97, (byte) 0x44, (byte) 0x17, (byte) 0xC4, (byte) 0xA7, (byte) 0x7E, (byte) 0x3D,
                    (byte) 0x64, (byte) 0x5D, (byte) 0x19, (byte) 0x73 },
            { (byte) 0x60, (byte) 0x81, (byte) 0x4F, (byte) 0xDC, (byte) 0x22, (byte) 0x2A, (byte) 0x90, (byte) 0x88, (byte) 0x46, (byte) 0xEE, (byte) 0xB8, (byte) 0x14,
                    (byte) 0xDE, (byte) 0x5E, (byte) 0x0B, (byte) 0xDB },
            { (byte) 0xE0, (byte) 0x32, (byte) 0x3A, (byte) 0x0A, (byte) 0x49, (byte) 0x06, (byte) 0x24, (byte) 0x5C, (byte) 0xC2, (byte) 0xD3, (byte) 0xAC, (byte) 0x62,
                    (byte) 0x91, (byte) 0x95, (byte) 0xE4, (byte) 0x79 },
            { (byte) 0xE7, (byte) 0xC8, (byte) 0x37, (byte) 0x6D, (byte) 0x8D, (byte) 0xD5, (byte) 0x4E, (byte) 0xA9, (byte) 0x6C, (byte) 0x56, (byte) 0xF4, (byte) 0xEA,
                    (byte) 0x65, (byte) 0x7A, (byte) 0xAE, (byte) 0x08 },
            { (byte) 0xBA, (byte) 0x78, (byte) 0x25, (byte) 0x2E, (byte) 0x1C, (byte) 0xA6, (byte) 0xB4, (byte) 0xC6, (byte) 0xE8, (byte) 0xDD, (byte) 0x74, (byte) 0x1F,
                    (byte) 0x4B, (byte) 0xBD, (byte) 0x8B, (byte) 0x8A },
            { (byte) 0x70, (byte) 0x3E, (byte) 0xB5, (byte) 0x66, (byte) 0x48, (byte) 0x03, (byte) 0xF6, (byte) 0x0E, (byte) 0x61, (byte) 0x35, (byte) 0x57, (byte) 0xB9,
                    (byte) 0x86, (byte) 0xC1, (byte) 0x1D, (byte) 0x9E },
            { (byte) 0xE1, (byte) 0xF8, (byte) 0x98, (byte) 0x11, (byte) 0x69, (byte) 0xD9, (byte) 0x8E, (byte) 0x94, (byte) 0x9B, (byte) 0x1E, (byte) 0x87, (byte) 0xE9,
                    (byte) 0xCE, (byte) 0x55, (byte) 0x28, (byte) 0xDF },
            { (byte) 0x8C, (byte) 0xA1, (byte) 0x89, (byte) 0x0D, (byte) 0xBF, (byte) 0xE6, (byte) 0x42, (byte) 0x68, (byte) 0x41, (byte) 0x99, (byte) 0x2D, (byte) 0x0F,
                    (byte) 0xB0, (byte) 0x54, (byte) 0xBB, (byte) 0x16 }
    };

    private final static byte[][] SBOX_INVERTIDA = {
            { (byte) 0x52, (byte) 0x09, (byte) 0x6A, (byte) 0xD5, (byte) 0x30, (byte) 0x36, (byte) 0xA5, (byte) 0x38, (byte) 0xBF, (byte) 0x40, (byte) 0xA3, (byte) 0x9E, (byte) 0x81, (byte) 0xF3, (byte) 0xD7, (byte) 0xFB },
            { (byte) 0x7C, (byte) 0xE3, (byte) 0x39, (byte) 0x82, (byte) 0x9B, (byte) 0x2F, (byte) 0xFF, (byte) 0x87, (byte) 0x34, (byte) 0x8E, (byte) 0x43, (byte) 0x44, (byte) 0xC4, (byte) 0xDE, (byte) 0xE9, (byte) 0xCB },
            { (byte) 0x54, (byte) 0x7B, (byte) 0x94, (byte) 0x32, (byte) 0xA6, (byte) 0xC2, (byte) 0x23, (byte) 0x3D, (byte) 0xEE, (byte) 0x4C, (byte) 0x95, (byte) 0x0B, (byte) 0x42, (byte) 0xFA, (byte) 0xC3, (byte) 0x4E },
            { (byte) 0x08, (byte) 0x2E, (byte) 0xA1, (byte) 0x66, (byte) 0x28, (byte) 0xD9, (byte) 0x24, (byte) 0xB2, (byte) 0x76, (byte) 0x5B, (byte) 0xA2, (byte) 0x49, (byte) 0x6D, (byte) 0x8B, (byte) 0xD1, (byte) 0x25 },
            { (byte) 0x72, (byte) 0xF8, (byte) 0xF6, (byte) 0x64, (byte) 0x86, (byte) 0x68, (byte) 0x98, (byte) 0x16, (byte) 0xD4, (byte) 0xA4, (byte) 0x5C, (byte) 0xCC, (byte) 0x5D, (byte) 0x65, (byte) 0xB6, (byte) 0x92 },
            { (byte) 0x6C, (byte) 0x70, (byte) 0x48, (byte) 0x50, (byte) 0xFD, (byte) 0xED, (byte) 0xB9, (byte) 0xDA, (byte) 0x5E, (byte) 0x15, (byte) 0x46, (byte) 0x57, (byte) 0xA7, (byte) 0x8D, (byte) 0x9D, (byte) 0x84 },
            { (byte) 0x90, (byte) 0xD8, (byte) 0xAB, (byte) 0x00, (byte) 0x8C, (byte) 0xBC, (byte) 0xD3, (byte) 0x0A, (byte) 0xF7, (byte) 0xE4, (byte) 0x58, (byte) 0x05, (byte) 0xB8, (byte) 0xB3, (byte) 0x45, (byte) 0x06 },
            { (byte) 0xD0, (byte) 0x2C, (byte) 0x1E, (byte) 0x8F, (byte) 0xCA, (byte) 0x3F, (byte) 0x0F, (byte) 0x02, (byte) 0xC1, (byte) 0xAF, (byte) 0xBD, (byte) 0x03, (byte) 0x01, (byte) 0x13, (byte) 0x8A, (byte) 0x6B },
            { (byte) 0x3A, (byte) 0x91, (byte) 0x11, (byte) 0x41, (byte) 0x4F, (byte) 0x67, (byte) 0xDC, (byte) 0xEA, (byte) 0x97, (byte) 0xF2, (byte) 0xCF, (byte) 0xCE, (byte) 0xF0, (byte) 0xB4, (byte) 0xE6, (byte) 0x73 },
            { (byte) 0x96, (byte) 0xAC, (byte) 0x74, (byte) 0x22, (byte) 0xE7, (byte) 0xAD, (byte) 0x35, (byte) 0x85, (byte) 0xE2, (byte) 0xF9, (byte) 0x37, (byte) 0xE8, (byte) 0x1C, (byte) 0x75, (byte) 0xDF, (byte) 0x6E },
            { (byte) 0x47, (byte) 0xF1, (byte) 0x1A, (byte) 0x71, (byte) 0x1D, (byte) 0x29, (byte) 0xC5, (byte) 0x89, (byte) 0x6F, (byte) 0xB7, (byte) 0x62, (byte) 0x0E, (byte) 0xAA, (byte) 0x18, (byte) 0xBE, (byte) 0x1B },
            { (byte) 0xFC, (byte) 0x56, (byte) 0x3E, (byte) 0x4B, (byte) 0xC6, (byte) 0xD2, (byte) 0x79, (byte) 0x20, (byte) 0x9A, (byte) 0xDB, (byte) 0xC0, (byte) 0xFE, (byte) 0x78, (byte) 0xCD, (byte) 0x5A, (byte) 0xF4 },
            { (byte) 0x1F, (byte) 0xDD, (byte) 0xA8, (byte) 0x33, (byte) 0x88, (byte) 0x07, (byte) 0xC7, (byte) 0x31, (byte) 0xB1, (byte) 0x12, (byte) 0x10, (byte) 0x59, (byte) 0x27, (byte) 0x80, (byte) 0xEC, (byte) 0x5F },
            { (byte) 0x60, (byte) 0x51, (byte) 0x7F, (byte) 0xA9, (byte) 0x19, (byte) 0xB5, (byte) 0x4A, (byte) 0x0D, (byte) 0x2D, (byte) 0xE5, (byte) 0x7A, (byte) 0x9F, (byte) 0x93, (byte) 0xC9, (byte) 0x9C, (byte) 0xEF },
            { (byte) 0xA0, (byte) 0xE0, (byte) 0x3B, (byte) 0x4D, (byte) 0xAE, (byte) 0x2A, (byte) 0xF5, (byte) 0xB0, (byte) 0xC8, (byte) 0xEB, (byte) 0xBB, (byte) 0x3C, (byte) 0x83, (byte) 0x53, (byte) 0x99, (byte) 0x61 },
            { (byte) 0x17, (byte) 0x2B, (byte) 0x04, (byte) 0x7E, (byte) 0xBA, (byte) 0x77, (byte) 0xD6, (byte) 0x26, (byte) 0xE1, (byte) 0x69, (byte) 0x14, (byte) 0x63, (byte) 0x55, (byte) 0x21, (byte) 0x0C, (byte) 0x7D },
    };

    private static int padding;

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

                byte[] textoCifrado = cifrar(Files.readAllBytes(file.toPath()), parseChave(chave));
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
                    System.out.print("Onde guardar o arquivo cifrado (a partir do diretório atual)? ");
                    caminhoDoArquivoDecifrado = System.getProperty("user.dir") + scanner.next();
                    path = Paths.get(caminhoDoArquivoDecifrado);

                    if (!Files.exists(path)) {
                        System.out.println("ERRO: caminho não encontrado.");
                    }

                } while (!Files.exists(path));

                byte[] textoDecifrado = decifrar(Files.readAllBytes(file.toPath()), parseChave(chave));
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

    private static byte[] decifrar(byte[] textoCifrado, byte[] chave) {
        int numBlocos = textoCifrado.length / 16;
        byte[] resultadoFinal = new byte[textoCifrado.length];

        byte[][] matrizDeEstado = gerarMatrizDeEstado(chave);
        byte[][] roundKeys = gerarRoundKeys(matrizDeEstado);
        roundKeys = expandirChave(roundKeys);

        for (int blocoIdx = 0; blocoIdx < numBlocos; blocoIdx++) {
            byte[] bloco = Arrays.copyOfRange(textoCifrado, blocoIdx * 16, (blocoIdx + 1) * 16);
            byte[][] temp = new byte[4][4];

            byte[][] estado = new byte[4][4];
            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    estado[i][j] = bloco[i + (j * 4)];
                }
            }

            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 4; k++) {
                    temp[j][k] = roundKeys[10][k];
                }
            }

            estado = addRoundKey(estado, temp);
            estado = inverterShiftRows(estado);
            estado = inverterSubstituirPalavras(estado);

            for (int i = 9; i > 0; i--) {
                for (int j = 0; j < 4; j++) {
                    for (int k = 0; k < 4; k++) {
                        temp[j][k] = roundKeys[i * 4 + j][k];
                    }
                }

                estado = addRoundKey(estado, temp);
                estado = inverterShiftRows(estado);
                estado = inverterSubstituirPalavras(estado);
            }

            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 4; k++) {
                    temp[j][k] = roundKeys[0][k];
                }
            }

            estado = addRoundKey(estado, temp);

            byte[] blocoDecifrado = flattenByteMatrix(estado);
            System.arraycopy(blocoDecifrado, 0, resultadoFinal, blocoIdx * 16, 16);
        }

        resultadoFinal = removerPadding(resultadoFinal);
        return resultadoFinal;
    }


    private static byte[][] inverterShiftRows(byte[][] estado) {
        byte[][] novoEstado = new byte[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                novoEstado[i][j] = estado[i][j];
            }
        }

        byte temp;
        temp = novoEstado[1][3];
        novoEstado[1][3] = novoEstado[1][2];
        novoEstado[1][2] = novoEstado[1][1];
        novoEstado[1][1] = novoEstado[1][0];
        novoEstado[1][0] = temp;

        temp = novoEstado[2][3];
        novoEstado[2][3] = novoEstado[2][2];
        novoEstado[2][2] = novoEstado[2][1];
        novoEstado[2][1] = novoEstado[2][0];
        novoEstado[2][0] = temp;

        temp = novoEstado[3][3];
        novoEstado[3][3] = novoEstado[3][2];
        novoEstado[3][2] = novoEstado[3][1];
        novoEstado[3][1] = novoEstado[3][0];
        novoEstado[3][0] = temp;

        return novoEstado;
    }

    private static byte[][] inverterSubstituirPalavras(byte[][] estado) {
        byte[][] novoEstado = new byte[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                byte valor = estado[i][j];

                int indice = valor & 0xFF;

                novoEstado[i][j] = SBOX_INVERTIDA[indice / 16][indice % 16];
            }
        }

        return novoEstado;
    }

    private static byte[] cifrar(byte[] textoSimples, byte[] chave) { // Adicionar padding
        textoSimples = aplicarPadding(textoSimples);
        int numBlocos = textoSimples.length / 16;
        byte[] resultadoFinal = new byte[textoSimples.length];
        byte[][] matrizDeEstado = gerarMatrizDeEstado(chave);
        byte[][] roundKeys = gerarRoundKeys(matrizDeEstado);
        roundKeys = expandirChave(roundKeys);

        for (int blocoIdx = 0; blocoIdx < numBlocos; blocoIdx++) {
            byte[] bloco = Arrays.copyOfRange(textoSimples, blocoIdx * 16, (blocoIdx + 1) * 16);
            byte[][] temp = new byte[4][4];
            byte[][] estado = new byte[4][4];

            for (int i = 0; i < 4; i++) {
                for (int j = 0; j < 4; j++) {
                    estado[i][j] = bloco[i + (j * 4)];
                }
            }

            estado = addRoundKey(estado, roundKeys);

            for (int i = 1; i < 10; i++) {
                estado = substituirPalavra02(estado);
                estado = shiftRows(estado);
                estado = mixColumns(estado);

                for (int j = 0; j < 4; j++) {
                    for (int k = 0; k < 4; k++) {
                        temp[j][k] = roundKeys[i * 4 + j][k];
                    }
                }

                estado = addRoundKey(estado, temp);
            }

            for (int j = 0; j < 4; j++) {
                for (int k = 0; k < 4; k++) {
                    temp[j][k] = roundKeys[10][k];
                }
            }

            estado = substituirPalavra02(estado);
            estado = addRoundKey(estado, temp);
            byte[] blocoCifrado = flattenByteMatrix(estado);
            System.arraycopy(blocoCifrado, 0, resultadoFinal, blocoIdx * 16, 16);
        }

        return resultadoFinal;
    }


    private static byte[] flattenByteMatrix(byte[][] byteMatrix) {
        int rows = byteMatrix.length;
        int cols = byteMatrix[0].length;
        byte[] flatArray = new byte[rows * cols];

        int index = 0;
        for (int i = 0; i < rows; i++) {
            for (int j = 0; j < cols; j++) {
                flatArray[index++] = byteMatrix[i][j];
            }
        }

        return flatArray;
    }

    private static byte[][] mixColumns(byte[][] matrizDeEstado) {
        for (int i = 0; i < 4; i++) {
            byte[] coluna = new byte[4];
            for (int j = 0; j < 4; j++) {
                coluna[j] = matrizDeEstado[j][i];
            }

            matrizDeEstado[0][i] = (byte) (multiplicarPor02(coluna[0]) ^ multiplicarPor03(coluna[1]) ^ coluna[2] ^ coluna[3]);
            matrizDeEstado[1][i] = (byte) (coluna[0] ^ multiplicarPor02(coluna[1]) ^ multiplicarPor03(coluna[2]) ^ coluna[3]);
            matrizDeEstado[2][i] = (byte) (coluna[0] ^ coluna[1] ^ multiplicarPor02(coluna[2]) ^ multiplicarPor03(coluna[3]));
            matrizDeEstado[3][i] = (byte) (multiplicarPor03(coluna[0]) ^ coluna[1] ^ coluna[2] ^ multiplicarPor02(coluna[3]));
        }

        return matrizDeEstado;
    }


    private static byte multiplicarPor02(byte b) {
        return (byte) ((b << 1) ^ ((b & 0x80) != 0 ? 0x1B : 0x00));
    }

    private static byte multiplicarPor03(byte b) {
        return (byte) (multiplicarPor02(b) ^ b);
    }

    private static byte[][] shiftRows(byte[][] matrizDeEstado) {
        byte temp;

        temp = matrizDeEstado[1][0];

        for (int i = 0; i < 3; i++) {
            matrizDeEstado[1][i] = matrizDeEstado[1][i + 1];
        }

        matrizDeEstado[1][3] = temp;

        temp = matrizDeEstado[2][0];
        matrizDeEstado[2][0] = matrizDeEstado[2][2];
        matrizDeEstado[2][2] = temp;

        temp = matrizDeEstado[2][1];
        matrizDeEstado[2][1] = matrizDeEstado[2][3];
        matrizDeEstado[2][3] = temp;

        temp = matrizDeEstado[3][0];
        matrizDeEstado[3][0] = matrizDeEstado[3][1];
        matrizDeEstado[3][1] = matrizDeEstado[3][2];
        matrizDeEstado[3][2] = matrizDeEstado[3][3];

        matrizDeEstado[3][3] = temp;

        return matrizDeEstado;
    }

    public static byte[][] addRoundKey(byte[][] estado, byte[][] roundKey) {
        byte[][] novoEstado = new byte[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                novoEstado[i][j] = (byte) (estado[i][j] ^ roundKey[i][j]);
            }
        }

        return novoEstado;
    }

    private static byte[] aplicarPadding(byte[] dados) {
        int tamanhoBloco = 16;
        int comprimentoDados = dados.length;
        int numeroPadBytes = tamanhoBloco - (comprimentoDados % tamanhoBloco);

        byte[] dadosComPadding = new byte[comprimentoDados + numeroPadBytes];
        System.arraycopy(dados, 0, dadosComPadding, 0, comprimentoDados);

        for (int i = comprimentoDados; i < dadosComPadding.length; i++) {
            dadosComPadding[i] = (byte) numeroPadBytes;
        }

        return dadosComPadding;
    }

    private static byte[] removerPadding(byte[] dados) {
        int comprimentoDados = dados.length;
        int numeroPadBytes = dados[comprimentoDados - 1];
        byte[] dadosSemPadding = new byte[comprimentoDados - numeroPadBytes];
        System.arraycopy(dados, 0, dadosSemPadding, 0, dadosSemPadding.length);

        return dadosSemPadding;
    }

    private static byte[][] gerarMatrizDeEstado(byte[] chave) {
        byte[][] matrizDeEstado = new byte[4][4];
        int contador = 0;

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                matrizDeEstado[i][j] = chave[contador];
                contador++;
            }
        }

        return matrizDeEstado;
    }

    private static byte[][] gerarRoundKeys(byte[][] matrizDeEstado) {
        byte[][] roundKeys = new byte[44][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                roundKeys[i][j] = matrizDeEstado[i][j];
            }
        }

        for (int i = 4; i < 44; i++) {
            byte[] temp = new byte[4];

            for (int j = 0; j < 4; j++) {
                temp[j] = roundKeys[i - 1][(j + 1) % 4];
            }

            for (int j = 0; j < 4; j++) {
                roundKeys[i][j] = (byte) (roundKeys[i - 4][j] ^ temp[j]);
            }
        }

        return roundKeys;
    }


    private static byte[][] expandirChave(byte[][] roundKeys) {
        byte[][] temp = new byte[1][4];
        byte[][] roundConstant;
        int contador = 1;

        for (int i = 0; i < 4; i++) {
            System.arraycopy(roundKeys[i], 0, temp[0], 0, 4);
            roundKeys[i] = temp[0].clone();
        }

        for (int i = 4; i < 44; i++) {
            if (i % 4 == 0) {
                temp[0] = rotacionarBytes(new byte[][] { roundKeys[i] })[0];
                temp = substituirPalavra01(temp);

                roundConstant = gerarRoundConstant(contador++);

                temp = xor(temp, roundConstant);

                for (int j = 0; j < 4; j++) {
                    roundKeys[i][j] = (byte) (roundKeys[i - 4][j] ^ temp[0][j]);
                }
            } else {
                for (int j = 0; j < 4; j++) {
                    roundKeys[i][j] = (byte) (roundKeys[i - 4][j] ^ roundKeys[i - 1][j]);
                }
            }
        }

        return roundKeys;
    }


    private static byte[][] xor(byte[][] subWord, byte[][] roundConstant) {
        byte[][] resultado = new byte[1][4];

        for (int i = 0; i < 4; i++) {
            resultado[0][i] = (byte) (subWord[0][i] ^ roundConstant[0][i]);
        }

        return resultado;
    }

    private static byte[][] gerarRoundConstant(int numero) {
        byte[][] roundConstant = new byte[1][4];

        switch (numero) {
            case 1:
                roundConstant[0][0] = (byte) 0x01;
                break;
            case 2:
                roundConstant[0][0] = (byte) 0x02;
                break;
            case 3:
                roundConstant[0][0] = (byte) 0x04;
                break;
            case 4:
                roundConstant[0][0] = (byte) 0x08;
                break;
            case 5:
                roundConstant[0][0] = (byte) 0x10;
                break;
            case 6:
                roundConstant[0][0] = (byte) 0x20;
                break;
            case 7:
                roundConstant[0][0] = (byte) 0x40;
                break;
            case 8:
                roundConstant[0][0] = (byte) 0x80;
                break;
            case 9:
                roundConstant[0][0] = (byte) 0x1B;
                break;
            case 10:
                roundConstant[0][0] = (byte) 0x36;
                break;
        }

        roundConstant[0][1] = (byte) 0x00;
        roundConstant[0][2] = (byte) 0x00;
        roundConstant[0][3] = (byte) 0x00;

        return roundConstant;
    }

    private static byte[][] substituirPalavra01(byte[][] palavra) {
        byte[][] resultado = new byte[1][4];

        for (int i = 0; i < 4; i++) {
            int fileira = (palavra[0][i] & 0xF0) >> 4;
            int coluna = (palavra[0][i] & 0x0F);
            resultado[0][i] = SBOX[fileira][coluna];
        }

        return resultado;
    }

    private static byte[][] substituirPalavra02(byte[][] palavra) {
        byte[][] resultado = new byte[4][4];

        for (int i = 0; i < 4; i++) {
            for (int j = 0; j < 4; j++) {
                int fileira = (palavra[i][j] & 0xF0) >> 4;
                int coluna = (palavra[i][j] & 0x0F);
                resultado[i][j] = SBOX[fileira][coluna];
            }
        }

        return resultado;
    }

    private static byte[][] rotacionarBytes(byte[][] palavra) {
        byte[][] temp = new byte[1][4];
        System.arraycopy(palavra[0], 0, temp[0], 0, 4);

        palavra[0][0] = temp[0][1];
        palavra[0][1] = temp[0][2];
        palavra[0][2] = temp[0][3];
        palavra[0][3] = temp[0][0];

        return palavra;
    }

    public static byte[] parseChave(String chave) {
        String[] stringArray = chave.split(",");

        byte[] bytes = new byte[stringArray.length];

        for (int i = 0; i < stringArray.length; i++) {
            bytes[i] = (byte) Integer.parseInt(stringArray[i]);
        }
        return bytes;
    }

    private static String gerarChaveAleatoria() {
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
