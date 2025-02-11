import java.io.*;
import java.net.Socket;
import java.net.ServerSocket;
import java.nio.file.StandardOpenOption;
import java.util.HashMap;
import java.util.Map;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.util.Base64;

/**
 * Class to handle the chat service (server)
 * The service is going to handle multiple clients and send it to everyone connected
 */
public class ServiceChat extends Thread {
    private BufferedReader input;

    static final int NBUSERSMAX = 3;
    static int nbUsers = 0; // Number of connected users.
    private static final String[] userNames = new String[NBUSERSMAX];
    public static PrintStream[] outputs = new PrintStream[NBUSERSMAX];

    private int BLOCK_SIZE = 240;

    private boolean isHeavyClient;
    private static final Map<String, FileTransfer> transferInProgress = new HashMap<>();

    private static final Map<String, String> credentials = new HashMap<>();
    private int userIndex;
    private String userName;

    private Socket socket;


    /**
     * Constructor of the class
     *
     * @param socket The socket of the client (telnet in my case)
     */
    public ServiceChat(Socket socket) {
        this.socket = socket;
    }

    public static void main(String[] args) {
        ServerSocket server;

        int port = 1234;

        if (args.length == 1) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                System.err.println("[X] - Error: Invalid port number: " + args[0]);
                System.err.println("[+] - Using default port: 1234");
                port = 1234;
            }
        }
        try {
            server = new ServerSocket(port);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        System.out.println("[+] - Server started on port " + port);
        System.out.println("[+] - Waiting for clients...");

        while (true) {
            Socket socket;
            try {
                socket = server.accept();
                System.out.println("[+] - New client connected.");
                new ServiceChat(socket).start();
            } catch (IOException e) {
                System.err.println("[X] - Error accepting client connection: " + e.getMessage());
            }
        }
    }

    private void detectClientType() throws IOException {
        PrintStream tempOutput = new PrintStream(socket.getOutputStream());
        tempOutput.println("[+] - You are about to enter a chat. Press ENTER to continue...");

        input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        String line = input.readLine(); // I wait until the client send me something

        if (line.isEmpty() || line.length() < 20) { // I check if it a telnet or not
            System.out.println("[+] - Client detected as LIGHT (Telnet)");
            tempOutput.println("[+] - You are a Light CLIENT !");
            isHeavyClient = false;
        } else { // I have done that the Heavy client have to send me a message during is connexion.
            System.out.println("[+] - Client detected as HEAVY (ClientChat)");
            tempOutput.println("[+] - You are an Heavy CLIENT !");
            isHeavyClient = true;
        }
    }



    private void sendClient(String message) throws IOException {
        PrintStream tempOutput = new PrintStream(socket.getOutputStream());
        tempOutput.println(message);
    }

    /**
     * Function that handle the authentification of an user.
     *
     * @return true if the user is authenticated | false otherwise
     */
    private boolean authenticate() throws IOException {
        PrintStream tempOutput = new PrintStream(socket.getOutputStream());
        tempOutput.println("[+] - Enter your login: ");
        String login = input.readLine();

        tempOutput.println("[+] - Enter your password: ");
        String password = input.readLine();

        if (login == null || password == null || login.trim().isEmpty() || password.trim().isEmpty()) {
            tempOutput.println("[X] - Invalid login or password.");
            return false;
        }

        login = login.trim();
        password = password.trim();

        synchronized (ServiceChat.class) {
            // I check if the user is already connected or not

            for (String name : userNames) {
                if(name != null && name.equalsIgnoreCase(login)) {
                    tempOutput.println("[X] - This user is already connected, maybe you have been hacked");
                    return false;
                }
            }

            // Check if the user is in the database
            if (credentials.containsKey(login)) {
                if(!credentials.get(login).equals(password)) {
                    tempOutput.println("[X] - Invalid password");
                    return false;
                }
            } else {
                credentials.put(login, password);
                tempOutput.println("[+] - You have been registered with login : " + login);
            }

            userName = login; // Everything is fine
        }

        return true;
    }

    /**
     * Function to initialize the input and output streams
     *
     * @return true if initialization is successful | false otherwise
     */
    private boolean initStream() {
        try {
            synchronized (ServiceChat.class) {
                if (nbUsers >= NBUSERSMAX) {
                    sendClient("[-] - Server is full, please try again later.");
                    socket.close();
                    return false;
                }
            }

            detectClientType();


            input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
            PrintStream tempOutput = new PrintStream(socket.getOutputStream());

            int attempts = 0;
            while(attempts < 3){
                if (!authenticate()) {
                    attempts++; // User failed to authenticate
                } else {
                    break;
                }
            }

            if(attempts >= 3) {
                tempOutput.println("[-] - Too many attempts for authentification Try again later.");
                socket.close();
                return false;
            }

            synchronized (ServiceChat.class) {
                userIndex = -1;
                for (int i = 0; i < NBUSERSMAX; i++) {
                    if (outputs[i] == null) { // I try to find a `null` position
                        userIndex = i;
                        break;
                    }
                }
                if (userIndex == -1) {
                    tempOutput.println("[X] - Server is full.");
                    socket.close();
                    return false;
                }

                outputs[userIndex] = tempOutput;
                userNames[userIndex] = userName;
                nbUsers++;

                tempOutput.println("[+] - Welcome " + userName + "!");
                broadcastMessage("\n[+] - " + userName + " joined the chat!");

                System.out.println("[+] - " + userName + " connected. Users: " + nbUsers);
                broadcastMessage("[+] - Number of users connected: " + nbUsers);
                return true;
            }
        } catch (IOException e) {
            System.err.println("[X] - Error initializing streams: " + e.getMessage());
            return false;
        }
    }

    /**
     * Function to send a message to all connected users
     *
     * @param message The message to broadcast
     */
    public static synchronized void broadcastMessage(String message) {
        for (int i = 0; i < NBUSERSMAX; i++) {
            PrintStream output = outputs[i];
            if (output != null) {
                output.println(message);
            }
        }
    }

    private void listUsers(){
        StringBuilder list = new StringBuilder("\n[+] - List of connected users: ");
        for(int i = 0; i < NBUSERSMAX; i++){
            if(userNames[i] != null){
                list.append("\n[>] - ").append(userNames[i]);
            }
        }
        outputs[userIndex].println(list);
    }


    private void parserCommand(String message, PrintStream output) {
        message = message.trim();

        if (!message.startsWith("/")) {
            String fullMessage = "<" + userName + "> " + message;
            broadcastMessage(fullMessage);
            return;
        }

        String[] parts = message.split("\\s+", 2);

        String command = parts[0];
        String content = (parts.length > 1) ? parts[1] : "";

        switch (command) {
            case "/help" -> {
                output.println("======================================");
                output.println("             JavaChat by me           ");
                output.println("======================================");
                output.println("[+] - List of available commands:");
                output.println("    /list - List all connected users");
                output.println("    /msgAll <message> - Send message to everyone");
                output.println("    /msgTo <username> <message> - Send a private message to a user (Something to hide ? :D)");
                output.println("    /quit - To disconnect from the chat");
                output.println("======================================");
            }
            case "/list" -> {
                listUsers();

            }
            case "/quit" -> {
                outputs[userIndex].println("[+] - Goodbye " + userName + "!");
                try {
                    socket.close();
                } catch (IOException e) {
                    System.err.println("[X] - Error closing socket: " + e.getMessage());
                }
            }
            case "/msgAll" -> {
                if (content.isEmpty()) {
                    output.println("[X] - Usage: /msgAll <message>");
                } else {
                    String fullMessage = "<" + userName + "> " + content;
                    System.out.println("[Chat] " + fullMessage);
                    broadcastMessage(fullMessage);
                }
            }
            case "/msgTo" -> {
                if (content.isEmpty()) {
                    output.println("[X] - Usage: /msgTo <username> <message>");
                } else {
                    String[] subParts = content.split("\\s+", 2);
                    if (subParts.length < 2) {
                        output.println("[X] - Usage: /msgTo <username> <message>");
                    } else {
                        String targetUser = subParts[0];
                        String privateMessage = subParts[1];

                        int targetIndex = findUserIndex(targetUser); // I get the user
                        if (targetIndex == -1) {
                            output.println("\n[X] - User '" + targetUser + "' not found");
                        } else {
                            if(privateMessage.startsWith("/FILE|")) {
                                System.out.println("[+] - File received from " + userName + " to " + targetUser);
                                handleFileReception(privateMessage, targetUser, targetIndex);
                            } else {
                                outputs[targetIndex].println("[Private] <" + userName + "> " + privateMessage);
                                output.println("[Private to " + targetUser + "] " + privateMessage);
                            }
                        }
                    }
                }
            }
            case "/fileResponse" -> {
                String[] tokens = content.split("\\s+");
                if(tokens.length < 3) {
                    output.println("[X] - Usage: /fileResponse <sender> <ACCEPT/REFUSE> <filename>"); // I check if the user want to get a file or not
                } else {
                    String sender = tokens[0];
                    String response = tokens[1];
                    String filename = tokens[2];
                    handleFileResponse(sender, response, filename);
                }
            }
            case "/sendFileTo" -> {
                if(!isHeavyClient){
                    output.println("[X] - You are not allowed to send file because you are a telnet client");
                }
            }

            default -> {
                output.println("[X] - Unknown command: " + command);
            }
        }
    }

    private void handleFileResponse(String sender, String response, String filename) {
        int senderIndex = findUserIndex(sender);

        if(senderIndex == -1) {
            outputs[userIndex].println("[X] - User '" + sender + "' not found");
            return;
        }

        FileTransfer fileT = transferInProgress.get(userName); // I have done an hashmap to store the file transfert in progress

        if(fileT == null) {
            outputs[userIndex].println("[X] - Nothing to transfert for this file " + filename);
            return;
        }

        if(response.equalsIgnoreCase("ACCEPT")) {
            outputs[senderIndex].println("[+] - " + userName + " accepted your file");
            sendFileToClient(fileT.filePath, userIndex);
        } else if(response.equalsIgnoreCase("REFUSE")) {
            outputs[senderIndex].println("[X] - " + userName + " refused your file");
            outputs[userIndex].println("[X] - You refused the file from " + sender);

            // Maybe I will have to delete the file there I don't know yet
        } else {
            outputs[senderIndex].println("[X] - Invalid response: " + response);
        }

        transferInProgress.remove(sender); // I remove from the hash map the transfer because that was is done or have been refused
    }

    private void sendFileToClient(String filePath, int targetIndex) {
        try {
            File file = new File(filePath);
            if (!file.exists()) {
                outputs[targetIndex].println("[X] - Error: File not found on server.");
                return;
            }

            // 1 - I encode the name of the file in Base64
            String encodedFilename = Base64.getEncoder().encodeToString(file.getName().getBytes());

            // 2 - I encode the content of the file in Base64
            byte[] fileContent = Files.readAllBytes(Paths.get(filePath));
            String encodedContent = Base64.getEncoder().encodeToString(fileContent);

            // 3 - I create the payload "/FILE|name|content"
            String message = userName + ">FILE|" + encodedFilename + "|" + encodedContent;

            // 4 - I send the file to the target
            outputs[targetIndex].println(message);
            outputs[userIndex].println("[+] - File successfully sent to " + userNames[targetIndex]);

        } catch (IOException e) {
            outputs[targetIndex].println("[X] - Error receiving file: " + e.getMessage());
            outputs[userIndex].println("[X] - Error sending file: " + e.getMessage());
        }
    }



    private void handleFileReception(String fileMessage, String targetUser, int targetIndex) {
        try {
            // I'm going to store the file in the received_files directory
            String[] fileParts = fileMessage.substring(6).split("\\|");

            if (fileParts.length < 2) {
                outputs[userIndex].println("[X] - Invalid file format received.");
                return;
            }

            //  1- I extract the name and the content of the file (still in Base64)
            String encodedFilename = fileParts[0];
            String encodedContent = fileParts[1];

            // 2 - Decode the filename and the content
            String filename = new String(Base64.getDecoder().decode(encodedFilename));
            byte[] fileContent = Base64.getDecoder().decode(encodedContent);

            // 3 - I save the file temporarily
            String filePath = "received_files/" + filename;
            Files.createDirectories(Paths.get("received_files"));
            Files.write(Paths.get(filePath), fileContent, StandardOpenOption.CREATE);

            System.out.println("[+] - File have been upload");

            transferInProgress.put(targetUser, new FileTransfer(userName, filename, filePath));

            outputs[targetIndex].println("[+] - " + userName + " sent you a file: " + filename);
            outputs[targetIndex].println("[?] - To download it type: /fileResponse " + userName + " ACCEPT " + filename);
            outputs[targetIndex].println("[?] - To refuse it type: /fileResponse " + userName + " REFUSE " + filename);

        } catch (Exception e) {
            outputs[userIndex].println("[X] - Error receiving file: " + e.getMessage());
        }
    }


    private int findUserIndex(String name) {
        for (int i = 0; i < NBUSERSMAX; i++) {
            if (userNames[i] != null && userNames[i].equalsIgnoreCase(name)) {
                return i;
            }
        }
        return -1;
    }


    /**
     * Main loop to read messages from the client and broadcast them
     */
    private void mainLoop() {
        try {

            String message;
            PrintStream currentOutput = outputs[userIndex];
            listUsers();
            currentOutput.println("[>] Enter message: ");
            currentOutput.flush(); // I had to add this line because the message was not displyed durint the good timing

            while ((message = input.readLine()) != null) {
                parserCommand(message, currentOutput);

                currentOutput.println("\n[>] Enter message: ");
                currentOutput.flush();
            }
        } catch (IOException e) {
            System.err.println("[X] - Client " + userName + " disconnected: " + e.getMessage());
        } finally {
            cleanup();
        }
    }

    /**
     * Cleanup resources when a client disconnects
     */
    private void cleanup() {
        synchronized (ServiceChat.class) {
            if (userName != null) {
                System.out.println("[+] - " + userName + " disconnected.");
                outputs[userIndex] = null;
                userNames[userIndex] = null;
                nbUsers--;

                broadcastMessage("\n[-] - " + userName + " left the chat.");
                broadcastMessage("[+] - Number of users connected: " + nbUsers);
            }
        }
        try {
            if (socket != null && !socket.isClosed()) {
                socket.close();
            }
        } catch (IOException e) {
            System.err.println("[X] - Error closing socket: " + e.getMessage());
        }
    }

    /**
     * Checks if a nickname is already in use
     *
     * @param nick Nickname to check
     * @return true if the nickname is already used | false otherwise
     */
    private boolean isNicknameAlreadyUsed(String nick) {
        for (int i = 0; i < NBUSERSMAX; i++) {
            if (nick.equalsIgnoreCase(userNames[i])) {
                return true;
            }
        }
        return false;
    }

    @Override
    public void run() {
        if (initStream()) {
            mainLoop();
        }
    }
}
