import java.io.File;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Scanner;

public class Trabalho01 {
    public static void main(String[] args) {
        boolean loop = true;
        Scanner scanner = new Scanner(System.in);

        while (loop) {

            System.out.print("Quer cifrar (C) ou decifrar (D)? S para sair:");
            String opcao = scanner.next();

            if (opcao.toLowerCase().equals("c")) {
                boolean arquivoExiste = true;
                File file;
                
                do {             
                    System.out.print("Entre o caminho do arquivo que quer cifrar:");            
                    String caminhoDoArquivo = scanner.next();
                    file = new File(caminhoDoArquivo);
    
                    if (file.exists()) {
                        arquivoExiste = true;
                    } else {
                        System.out.println("Arquivo não encontrado.");
                        arquivoExiste = false;                       
                    }

                } while (!arquivoExiste);

                String textoCifrado = cifrar(file.toString());
                Path path;
                arquivoExiste = true;

                do {             
                    System.out.print("Onde guardar o arquivo cifrado?");            
                    String caminhoDoArquivo = scanner.next();
                    path = Paths.get(caminhoDoArquivo);
    
                    if (!Files.exists(path)) {
                        System.out.println("Caminho não encontrado.");
                        arquivoExiste = false;
                    } else {
                        arquivoExiste = true;
                    }

                    if (Files.exists(path)) {
                        arquivoExiste = true;
                    } else {
                        System.out.println("Caminho não encontrado.");
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
                    System.out.print("Entre o caminho do arquivo que quer decifrar:");            
                    String caminhoDoArquivo = scanner.next();
                    file = new File(caminhoDoArquivo);
    
                    if (file.exists()) {
                        arquivoExiste = true;
                    } else {
                        System.out.println("Arquivo não encontrado.");
                        arquivoExiste = false;                       
                    }

                } while (!arquivoExiste);

                String textoDecifrado = decifrar(file.toString());
                Path path;
                arquivoExiste = true;

                do {             
                    System.out.print("Onde guardar o arquivo decifrado?");            
                    String caminhoDoArquivo = scanner.next();
                    path = Paths.get(caminhoDoArquivo);
    
                    if (!Files.exists(path)) {
                        System.out.println("Caminho não encontrado.");
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
                System.out.println("Opção inválida.");

            }

        } 

        scanner.close();

    }

    public static String cifrar(String texto) {
        return "foo";
    }

    public static String decifrar(String texto) {
        return "foo";
    }
}