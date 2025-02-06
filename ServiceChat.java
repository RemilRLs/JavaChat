import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.IOException;
import java.net.Socket;
import java.net.ServerSocket;
import java.util.HashMap;
import java.util.Map;

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


    private static final Map<String, String> credentials = new HashMap<>();
    private int userIndex;
    private String userName;

    private Socket socket; // Socket client

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
        String list = "[+] - List of connected users: ";
        for(int i = 0; i < NBUSERSMAX; i++){
            if(userNames[i] != null){
                list += userNames[i] + " ";
            }
        }
        outputs[userIndex].println(list);
    }

    /**
     * Send a message to a specific client
     */
    private void sendMessage(String message) {
        //output.println(message);
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
                outputs[userIndex].println("Goodbye " + userName + "!");
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
                            output.println("[X] - User '" + targetUser + "' not found");
                        } else {

                            outputs[targetIndex].println("[Private] <" + userName + "> " + privateMessage);
                            output.println("[Private to " + targetUser + "] " + privateMessage);
                        }
                    }
                }
            }
            default -> {
                output.println("[X] - Unknown command: " + command);
            }
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
            currentOutput.print("[>] Enter message: ");

            while ((message = input.readLine()) != null) {
                parserCommand(message, currentOutput);

                currentOutput.print("\n[>] Enter message: ");
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
