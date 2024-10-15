import java.util.Scanner;

public class Trabalho01 {
    public static void main(String[] args) {

        while (true) {
            Scanner scanner = new Scanner(System.in);

            System.out.println("Quer criptografar (C) ou descriptografar (D)? S para sair.");
            String opcao = scanner.next();

            if (opcao.toLowerCase().equals("c")) {

            } else if (opcao.toLowerCase().equals("d")) {

            } else if (opcao.toLowerCase().equals("s")) {
                break;
            } else {
                System.out.println("Opção inválida.");
            }
        }
        
    }
}