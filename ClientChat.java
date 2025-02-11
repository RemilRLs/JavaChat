import java.io.*;
import java.net.Socket;
import java.nio.file.Path;
import java.util.Base64;
import java.nio.file.Files;
import java.nio.file.Paths;

public class ClientChat {


    private String serverHost = "localhost";
    private int serverPort = 1234;

    private int BLOCK_SIZE = 240; // For send a file block by block (Javacard)

    private BufferedReader inputNetwork;
    private BufferedReader inputConsole;

    private PrintStream outputNetwork;
    private PrintStream outputConsole;

    private Socket socket;

    private boolean running = true;

    public static void main(String[] args) {
        ClientChat client = new ClientChat(args);
    }

    public ClientChat(String [] args) {
        initStreams(args);
        start();
        listenConsole();
    }

    void initStreams(String[] args) {
        if (args.length > 0) {
            serverHost = args[0];
        }
        if (args.length > 1) {
            try {
                serverPort = Integer.parseInt(args[1]);
            } catch (NumberFormatException e) {
                System.err.println("[X] - Error: " + e.getMessage());
                serverPort = 1234;
            }
        }
        System.out.println("[+] - Connexion to " + serverHost + ":" + serverPort);
    }

    void start() {
        try {
            socket = new Socket(serverHost, serverPort);

            inputNetwork = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            inputConsole = new BufferedReader(new InputStreamReader(System.in));

            outputNetwork = new PrintStream(socket.getOutputStream());
            outputConsole = System.out;

            String serverMessage = inputNetwork.readLine();
            outputConsole.println(serverMessage);

            Thread.sleep(500);
            outputNetwork.println("[+] - I swear that I'm a heavy client");

            Thread readThread = new Thread(new ServerListener());
            readThread.start();

        } catch (IOException e) {
            System.err.println("[X] - Error during connection: " + e.getMessage());
        } catch (InterruptedException e) {
            throw new RuntimeException(e);
        }
    }

    boolean parseCommand(String command) throws IOException {
        if (command.equalsIgnoreCase("/quit")) {
            outputNetwork.println("/quit");
            outputConsole.println("[*] - You left the chat, goodbye :(");

            try {
                socket.close();
                System.out.println("[+] - Socket has been closed.");
            } catch (IOException e) {
                System.err.println("[X] - Error closing socket: " + e.getMessage());
            }
            return true;

        } else if (command.toLowerCase().startsWith("/sendfileto ")) {
            String[] parts = command.split("\\s+", 2);

            if (parts.length < 2) {
                outputConsole.println("[X] - Usage: /sendfileto <file> <user>");
                return false;
            }

            String commandSend = parts[0];
            String content = parts[1];

            System.out.println("Command: " + commandSend);
            System.out.println("Content: " + content);

            if(content.isEmpty()) {
                outputConsole.println("[X] - Usage: /sendFileTo <file> <user>");
            } else {
                String[] subParts = content.split("\\s+", 2);
                if (subParts.length < 2) {
                    outputConsole.println("[X] - Usage: /sendFileTo <username> <message>");
                } else {
                    String targetFile = subParts[0];
                    String targetUser = subParts[1];

                    sendFile(targetFile, targetUser);

                    return false;
                }
            }
        }

        return false;
    }


    void sendFile(String filePath, String targetUser) {
        File file = new File(filePath);

        if (!file.exists() || !file.isFile()) {
            outputConsole.println("[X] - Error: File does not exist or is not a valid file.");
            return;
        }

        try {
            outputConsole.println("[+] - Preparing file: " + filePath + " for user: " + targetUser);

            // I encode the name of the file in Base64
            String encodedFilename = Base64.getEncoder().encodeToString(file.getName().getBytes());

            // Same for the content
            byte[] fileContent = Files.readAllBytes(Paths.get(filePath));
            String encodedContent = Base64.getEncoder().encodeToString(fileContent);

            // Then I send with that format: /msgTo <targetUser> /FILE|<encodedFilename>|<encodedContent>
            String message = "/msgTo " + targetUser + " /FILE|" + encodedFilename + "|" + encodedContent;

            outputNetwork.println(message);
            outputConsole.println("[+] - File sent successfully!");

        } catch (IOException e) {
            outputConsole.println("[X] - Error sending file: " + e.getMessage());
        }
    }

    void listenConsole() {
        try {
            String userInput;
            while (running) {

                if(inputConsole == null) { // I add that (TODO)
                    return;
                }

                userInput = inputConsole.readLine().trim();


                if(userInput.isEmpty()) {
                    continue;
                }

                if (userInput.startsWith("/")) {
                    boolean shouldQuit = parseCommand(userInput);
                    if (shouldQuit) {
                        break;
                    }
                }

                if(userInput.startsWith("/sendFileTo")) {
                    continue;
                }

                outputNetwork.println(userInput);
            }
        } catch (IOException e) {
            System.err.println("[X] - Error somewhere: " + e.getMessage());
        } finally {
            System.out.println("[*] - Exiting console listener...");
        }
    }

    void listenNetwork() {
        try {
            String line;
            while ((line = inputNetwork.readLine()) != null) {
                if (line.contains("FILE|")) {
                    String[] parts = line.split("\\|");

                    if (parts.length < 3) {
                        outputConsole.println("[X] - Invalid file format");
                        continue;
                    }

                    String pseudoSender = parts[0].split(">")[0];
                    String encodedFileName = parts[1];
                    String encodedFileContent = parts[2];

                    System.out.println("Pseudo sender: " + pseudoSender);
                    System.out.println("Encoded file name: " + encodedFileName);
                    System.out.println("Encoded file content: " + encodedFileContent);

                    String decodedFilename = new String(Base64.getDecoder().decode(encodedFileName));
                    byte[] decodedContent = Base64.getDecoder().decode(encodedFileContent);

                    File receivedFile = new File("received_" + decodedFilename);

                    try (FileOutputStream fileOutput = new FileOutputStream(receivedFile)) {
                        fileOutput.write(decodedContent);
                        fileOutput.flush();
                        outputConsole.println("[+] - File received and saved as: " + receivedFile.getAbsolutePath());
                    } catch (IOException e) {
                        outputConsole.println("[X] - Error writing file: " + e.getMessage());
                    }
                    continue;
                }


                outputConsole.println(line);

            }
        } catch (IOException e) {
            System.err.println("[X] - Error: " + e.getMessage());
        } finally {
            outputConsole.println("[*] - The server closed the connection :( Can't communicate anymore");
            running = false;
        }
    }


    private class ServerListener implements Runnable {
        @Override
        public void run() {
            listenNetwork();
        }
    }

}