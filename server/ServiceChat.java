import java.io.*;
import java.net.Socket;
import java.net.ServerSocket;
import java.util.HashMap;
import java.util.Map;
import java.util.Base64;
import java.util.Random;
import java.util.logging.*;
import java.math.BigInteger;
import java.util.Arrays;
import java.security.KeyFactory;
import java.security.PublicKey;
import java.security.spec.RSAPublicKeySpec;
import javax.crypto.Cipher;


public class ServiceChat extends Thread {
    private static final Logger LOGGER = Logger.getLogger(ServiceChat.class.getName());

    private BufferedReader input;

    static final int NBUSERSMAX = 3;
    static int nbUsers = 0;
    private static final String[] userNames = new String[NBUSERSMAX];
    public static PrintStream[] outputs = new PrintStream[NBUSERSMAX];

    private boolean isHeavyClient;
    private static final Map<String, FileTransfer> transferInProgress = new HashMap<>();

    private static final Map<String, String> userPasswords = new HashMap<>();  // For light client
    private static final Map<String, String> userPublicKeys = new HashMap<>(); // For heavy client
    private static final Map<String, Boolean> isHeavyClientMap = new HashMap<>();


    private int userIndex;
    private String userName;

    private Socket socket;
    private static Thread shutdownThread = null;


    public ServiceChat(Socket socket) {
        this.socket = socket;
    }

    /**
     * Function to start the logger
     */
    private static void loggerStart() {
        LOGGER.setUseParentHandlers(false);

        ConsoleHandler consoleHandler = new ConsoleHandler();
        consoleHandler.setLevel(Level.ALL);
        consoleHandler.setFormatter(new SimpleFormatter());
        LOGGER.addHandler(consoleHandler);
        LOGGER.setLevel(Level.ALL);


    }

    public static void main(String[] args) {
        loggerStart();
        ServerSocket server;

        int port = 1234; // Default port

        if (args.length == 1) {
            try {
                port = Integer.parseInt(args[0]);
            } catch (NumberFormatException e) {
                LOGGER.warning("[X] - Error: Invalid port number: " + args[0]);
                LOGGER.info("[+] - Using default port: 1234");
                port = 1234;
            }
        }
        try {
            server = new ServerSocket(port);
        } catch (IOException e) {
            throw new RuntimeException(e);
        }
        LOGGER.info("[+] - Server started on port " + port);
        LOGGER.info("[+] - Waiting for clients...");

        new Thread(ServiceChat::adminConsole).start();

        while (true) {
            Socket socket;
            try {
                socket = server.accept(); // I wait for a new client
                LOGGER.info("[+] - New client connected: " + socket.getInetAddress());
                new ServiceChat(socket).start();
            } catch (IOException e) {
                LOGGER.warning("[X] - Error during acceptation of client: " + e.getMessage());
            }
        }
    }

    /**
     * Function to start the admin console and to allow the administrator to send and make privileged actions
     *
     */
    private static void adminConsole() {
        BufferedReader console = new BufferedReader(new InputStreamReader(System.in));

        LOGGER.info("[+] - Admin console started !");

        while (true) {
            try {
                System.out.print("> ");
                String command = console.readLine();
                if (command == null) {
                    continue;
                }

                if(command.startsWith("/")) {
                    String[] parts = command.split("\\s+");
                    switch(parts[0]) {
                        case "/help" -> {
                            displayHelpAdmin();
                        }
                        case "/list" -> {
                            System.out.println("[+] - List of connected users:");
                            for (int i = 0; i < NBUSERSMAX; i++) {
                                if (userNames[i] != null) {
                                    System.out.println("[>] - " + userNames[i]);
                                }
                            }
                        }
                        case "/kill" -> {
                            if(parts.length != 2) {
                                System.out.println("[X] - Usage: /kill <username>");
                            } else {
                                killUser(parts[1]);
                            }
                        }
                        case "/shutdown" -> {
                            if(parts.length != 2) {
                                System.out.println("[X] - Usage: /shutdown <nb_minute_before_shutdown>");
                            }
                            else {
                                int minutes = Integer.parseInt(parts[1]);
                                shutdownCommand(minutes);
                            }
                        }
                    }
                } else {
                    broadcastMessage("[SYSTEM] " + command);
                    System.out.println("[SYSTEM] " + command);
                }
            } catch (IOException e) {
                LOGGER.warning("[X] - Error during a command of the admin console : " + e.getMessage());
            }
        }
    }

    // ======================== COMMAND ========================

    /**
     * Function to display the help message for heavy and light client
     * @param output Outut stream user
     */
    private void displayHelp(PrintStream output) {
        boolean isHeavy = isHeavyClientMap.getOrDefault(userName, false);


        output.println("======================================");
        output.println("             JavaChat by me           ");
        output.println("======================================");
        output.println("[+] - List of available commands:");
        output.println("    /list - List all connected users");
        output.println("    /msgAll <message> - Send message to everyone");
        output.println("    /msgTo <username> <message> - Send a private message to a user (Something to hide ? :D)");
        output.println("    /quit - To disconnect from the chat");

        if (isHeavy) {
            output.println("    /sendAllC <message> - Send an encrypted message");
            output.println("    /sendFileC <user> <file> - Send file to user (only Heavy Client)");
        } else {
            output.println("[X] - Some command are not available for you");
        }

        output.println("======================================");
    }

    /**
     * Function to display the /help command for the admin
     */
    private static void displayHelpAdmin() {
        System.out.println("======================================");
        System.out.println("             JavaChat by me           ");
        System.out.println("======================================");
        System.out.println("[+] - List of available commands:");
        System.out.println("    /list - List all connected users");
        System.out.println("    /kill <username> - Disconnect a user");
        System.out.println("    /shutdown <nb_minute_before_shutdown> - Shutdown the server in x minutes");
        System.out.println("======================================");
    }

    /**
     * Function to kill (make quit a user) a user
     * @param username The username of the user that we want to kick from the chat
     */
    private static void killUser(String username) {
        int index = findUserIndex(username);

        if(index == -1) {
            LOGGER.warning("[X] - User " + username + " not found");
            return;
        }

        outputs[index].println("[X] - You have been disconnected by the admin");
        outputs[index].close();
        outputs[index] = null;
        userNames[index] = null;
        LOGGER.info("[+] - User " + username + " has been disconnected by the admin");
    }

    /**
     * Function to shutdown the server in x minutes
     * @param minutes number of minute before shutdown
     */
    private static void shutdownCommand(int minutes) {
        System.out.println("[+] - Server will shutdown in " + minutes + " minutes");
        broadcastMessage("[SYSTEM] - Server will shutdown in " + minutes + " minutes");

        shutdownThread = new Thread(() -> {
            try {
                Thread.sleep(minutes * 60 * 1000);
                LOGGER.info("[+] - Server is shutting down...");
                broadcastMessage("[SYSTEM] - Server is shutting down...");

                System.exit(0);
            } catch (InterruptedException e) {
               LOGGER.warning("[X] - Error during shutdown: " + e.getMessage());
            }
        });

        shutdownThread.start();
    }

    /**
     * Function to list all user that are connected
     */
    private void listUsers(){
        StringBuilder list = new StringBuilder("\n[+] - List of connected users: ");
        for(int i = 0; i < NBUSERSMAX; i++){
            if(userNames[i] != null){
                list.append("\n[>] - ").append(userNames[i]);
            }
        }
        outputs[userIndex].println(list);
    }

    /**
     * Function to detect the type of client (Heavy or Light)
     */
    private void detectClientType() throws IOException {

        final String MAGIC_NUMBER = "TVRVeElEUXdJREUxTkNBeE5UY2dNVFkySURFME5TQTBNQ0F4TlRJZ01UUXhJREUyTmlBeE5ERT0=";

        PrintStream tempOutput = new PrintStream(socket.getOutputStream());
        tempOutput.println("[+] - You are about to enter a chat. Press ENTER to continue...");

        input = new BufferedReader(new InputStreamReader(socket.getInputStream()));
        String line = input.readLine(); // I wait until the client send me something

        if (line != null && line.equals(MAGIC_NUMBER)) {
            LOGGER.info("[+] - Client detected as HEAVY (JavaChat)");
            tempOutput.println("[+] - You are a Heavy CLIENT !");
            isHeavyClient = true;
        } else {
            LOGGER.info("[+] - Client detected as LIGHT (Telnet)");
            tempOutput.println("[+] - You are a Light CLIENT !");
            isHeavyClient = false;
        }
    }


    /**
     * Function to send a message to a specific user
     * @param message The message to send
     */
    private void sendClient(String message) throws IOException {
        PrintStream tempOutput = new PrintStream(socket.getOutputStream());
        tempOutput.println(message);
    }

    // ======================== AUTHENTICATION ========================

    /**
     * Function that handle the authentification of an user.
     *
     * @return true if the user is authenticated | false otherwise
     */
    private boolean authenticate() throws IOException {
        PrintStream tempOutput = new PrintStream(socket.getOutputStream());
        tempOutput.println("[+] - Enter your username: ");
        String login = input.readLine();

        if (login == null || login.trim().isEmpty()) {
            tempOutput.println("[X] - Invalid login");
            LOGGER.info("[X] - Invalid username have been enter by the user : " + socket.getInetAddress());
            return false;
        }

        login = login.trim();

        synchronized (ServiceChat.class) {
            // I check first if the user is already connected
            for (String name : userNames) {
                if (name != null && name.equalsIgnoreCase(login)) {
                    tempOutput.println("[X] - This user is already connected");
                    return false;
                }
            }

            // I have two mod of authentification one for heavy and one for light
            if (isHeavyClient) {
                isHeavyClientMap.put(login, true);
                LOGGER.info("[+] - Heavy client detected: " + login);
                return authenticateHeavyClient(login, tempOutput);
            } else {
                LOGGER.info("[+] - Light client detected: " + login);
                return authenticateLightClient(login, tempOutput);
            }
        }
    }

    /**
     * Function to authenticate a light client
     * @param login Username of the user
     * @param output The output stream of the user
     * @return  false if wrong password | true if good passwd or new user
     */
    private boolean authenticateLightClient(String login, PrintStream output) throws IOException {
        output.println("[+] - Enter your password : ");
        String password = input.readLine();

        if (password == null || password.trim().isEmpty()) {
            output.println("[X] - Invalid password");
            LOGGER.info("[X] - Invalid password have been enter by the user : " + login);
            return false;
        }

        password = password.trim();

        // I check if the user already exist
        if (userPasswords.containsKey(login)) {
            if (!userPasswords.get(login).equals(password)) {
                output.println("[X] - Invalid password");
                LOGGER.info("[X] - Invalid password have been enter by the user : " + login);
                return false;
            }
        } else { // I never saw the user there
            userPasswords.put(login, password);
            output.println("[+] - You have been registered with username: " + login);
        }

        LOGGER.info("[+] - User " + login + " have been authenticated (light client)");
        userName = login;
        return true;
    }

    /**
     * Function to authenticate a heavy client with challenge-response
     * @param login The username of the user
     * @param output The output stream of the user
     */
    private boolean authenticateHeavyClient(String login, PrintStream output) throws IOException {

        // I do the same as light but now I need to send a challenge to the user
        if (userPublicKeys.containsKey(login)) { // I check if I have already the public key of the user
            output.println("[+] - You are a registered user. We going to send you an authentication challenge...");

            try {
                String storedKey = userPublicKeys.get(login);
                String[] keyParts = storedKey.split(":");

                byte[] modulusBytes = Base64.getDecoder().decode(keyParts[0]);
                byte[] exponentBytes = Base64.getDecoder().decode(keyParts[1]);

                BigInteger modulus = new BigInteger(1, modulusBytes);
                BigInteger exponent = new BigInteger(1, exponentBytes);
                RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);
                PublicKey pubKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);

                final int CHALLENGE_SIZE = 64;
                byte[] clearChallenge;

                do { // Generation of a challenge
                    clearChallenge = new byte[CHALLENGE_SIZE];
                    new Random().nextBytes(clearChallenge);
                } while (new BigInteger(1, clearChallenge).compareTo(modulus) >= 0); // I need to do this because sometime the challenge is bigger than the modulus so that cause problem

                LOGGER.info("[+] - Challenge generated for " + login);

                byte[] encryptedChallenge = encryptChallenge(clearChallenge, pubKey);
                String challengeBase64 = Base64.getEncoder().encodeToString(encryptedChallenge);

                output.println("/challenge " + challengeBase64);
                LOGGER.info("[+] - Encrypted challenge sent to " + login);

                boolean challengeValid = verifyChallengeResponse(output, clearChallenge);
                if (challengeValid) { // I check if the challenge that have been sent to the server is the same as the one that have been geenrated by the server
                    userName = login;
                    return true;
                } else {
                    return false;
                }

            } catch (Exception e) {
                System.err.println("[X] - Cannot retrieve the public key from : " + login + ": " + e.getMessage());
                return false;
            }
        } else {
            output.println("[+] - You are a new user. Please provide your RSA public key in Base64");
            boolean gotKey = waitPublicKey(login, output);
            if (gotKey) {
                userName = login;
            }
            return gotKey;
        }
    }

    /**
     * Check the challenge between the original (that I generat with the server) and the other one that the user gave me
     * If that one is the same I authenticate the user
     * @param output The output stream of user
     * @param originalChallenge The challenge that have been generated by the server
     * @return true if the challenge is valid | false otherwise
     */
    private boolean verifyChallengeResponse(PrintStream output, byte[] originalChallenge) throws IOException {
        String response = input.readLine();

        if (response == null || !response.startsWith("/challengeResponse ")) {
            LOGGER.warning("[X] - Invalid challenge format");
            output.println("[X] - Invalid challenge format");
            return false;
        }

        LOGGER.info("[+] - Checking the challenge from client...");

        String decodedResponseBase64 = response.replace("/challengeResponse ", "").trim();
        byte[] decodedResponse = Base64.getDecoder().decode(decodedResponseBase64);



        if (Arrays.equals(decodedResponse, originalChallenge)) { // Good challenge
            output.println("[+] - Authentication successful");
            LOGGER.info("[+] - Challenge match !");
            return true;
        } else {
            output.println("[X] - Authentication failed.  You didn't pass the challenge");
            LOGGER.info("[X] - Challenge doesn't match !");
            return false;
        }
    }

    /**
     * Function to encrypt the challenge twith the public key of the user
     * @param clearChallenge The challenge that have been generated by the server
     * @param pubKey The public key of the user
     * @return The challenge encrypted
     */
    private byte[] encryptChallenge(byte[] clearChallenge, PublicKey pubKey) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA/ECB/NoPadding");
        cipher.init(Cipher.ENCRYPT_MODE, pubKey);
        return cipher.doFinal(clearChallenge);
    }

    /**
     * Function to get the public key of a heavy client during registration
     * @param login The username of the user
     * @param output The output stream of the user
     */
    private boolean waitPublicKey(String login, PrintStream output) throws IOException {
        while (true) {
            String line = input.readLine();
            if (line == null) {
                output.println("[X] - The connexion have been closed before the server received the public key");
                LOGGER.info("[X] - The connexion have been closed before the server received the public key");
                return false;
            }

            if (line.startsWith("/sendPublicKey ")) { // The user try to send me his public key
                String[] parts = line.split(" ", 3);
                if (parts.length != 3) {
                    output.println("[X] - Usage: /sendPublicKey <modulusB64> <exponentB64>");
                    continue;
                }

                String modB64 = parts[1].trim();
                String expB64 = parts[2].trim();

                // I put the public key in the map
                userPublicKeys.put(login, modB64 + ":" + expB64);
                output.println("[+] - Public key registered. Please reconnect to authenticate (a challenge will be given to you)");
                LOGGER.info("[+] - Public key registered for " + login);
                socket.close();
                return false;
            } else {
                output.println("[X] - Please type: /sendPublicKey <modulusB64> <exponentB64>");
                LOGGER.info("[X] - Invalid command from " + login);
            }
        }
    }


    /**
     * Function to initialize the input and output streams (communication with client)
     * also I do authentification here and I have a security with 3 attempts
     * @return true if initialization is successful | false otherwise
     */
    private boolean initStream() {
        try {

            synchronized (ServiceChat.class) {
                if (nbUsers >= NBUSERSMAX) {
                    sendClient("[-] - Server is full, please try again later");
                    LOGGER.info("[X] - A user try to connect but the server is full");
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
                tempOutput.println("[-] - Too many attempts for authentification Try again later");
                LOGGER.info("[X] - Too many attempts for authentification from " + socket.getInetAddress());
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
                    tempOutput.println("[X] - Server is full");
                    socket.close();
                    return false;
                }

                outputs[userIndex] = tempOutput;
                userNames[userIndex] = userName;
                nbUsers++; // I add a user

                tempOutput.println("[+] - Welcome " + userName + "!");
                broadcastMessage("\n[+] - " + userName + " joined the chat!");

                System.out.println("[+] - " + userName + " connected |  Users: " + nbUsers);
                broadcastMessage("[+] - Number of users connected: " + nbUsers);
                LOGGER.info("[+] - User " + userName + " connected | Users: " + nbUsers);
                return true;
            }
        } catch (IOException e) {
            System.err.println("[+] - DEBUG: " + e.getMessage());
            return false;
        }
    }

    /**
     * That one is for sending message to all user but for light client
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

    /**
     * Function to handle public key registration (so new heavy client detected)
     * @param user The username of the user
     * @param message The message that will contain the public key
     */
    private void handlePublicKeyRegistration(String user, String message) {
        try {
            String[] parts = message.split(" ");
            if (parts.length != 4) { // I get here my public key of the client
                System.err.println("[X] - Invalid public key format from " + user);
                return;
            }

            String modulusBase64 = parts[2];
            String exponentBase64 = parts[3];

            byte[] modulusBytes = Base64.getDecoder().decode(modulusBase64);
            byte[] exponentBytes = Base64.getDecoder().decode(exponentBase64);

            BigInteger modulus = new BigInteger(1, modulusBytes);
            BigInteger exponent = new BigInteger(1, exponentBytes);
            RSAPublicKeySpec keySpec = new RSAPublicKeySpec(modulus, exponent);

            //PublicKey publicKey = KeyFactory.getInstance("RSA").generatePublic(keySpec);

            LOGGER.info("[+] - Public key received from " + user);


        } catch (Exception e) {
            System.err.println("[X] - Error handling public key from " + user + ": " + e.getMessage());
        }
    }

    /**
     * To parse command of the user
     * @param message The message to parse (command)
     * @param output The output stream of the user
     */
    private void parserCommand(String message, PrintStream output) {
        message = message.trim();

        if (!message.startsWith("/")) {
            String fullMessage = "<" + userName + "> " + message;
            broadcastMessage(fullMessage);
            return;
        }

        String[] parts = message.split("\\s+", 2);

        String command = parts[0];
        String content;
        if (parts.length > 1) {
            content = parts[1];
        } else {
            content = "";
        }

        switch (command) {
            case "/help" -> {
                displayHelp(output);
            }
            case "/list" -> {
                listUsers();
            }

            case "/quit" -> {
                outputs[userIndex].println("[+] - Goodbye " + userName + "!");
                LOGGER.info("[+] - User " + userName + " disconnected");
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

                        int targetIndex = findUserIndex(targetUser);
                        if (targetIndex == -1) {
                            output.println("\n[X] - User '" + targetUser + "' not found");
                        } else {
                            boolean isTargetHeavy = isHeavyClientMap.getOrDefault(targetUser, false);
                            boolean isSenderHeavy = isHeavyClientMap.getOrDefault(userName, false);

                            // File cipher
                            if (privateMessage.startsWith("/FILEC|")) {
                                if (isTargetHeavy) { // I only send if the target is a heavy client
                                    outputs[targetIndex].println("[Private] <" + userName + "> " + privateMessage);
                                    LOGGER.info("[+] - File sent to " + targetUser);
                                } else {
                                    output.println("[X] - User " + targetUser + " is not a heavy so that one cannot receive the file");
                                    LOGGER.info("[X] - User try to send a file to a light client : " + targetUser);
                                }
                            } else {
                                // So if the message is sent between two heavy clients I sent the message (that one is ciphered)
                                if (isSenderHeavy && isTargetHeavy) {
                                    outputs[targetIndex].println("/C " + userName + " (private) " + privateMessage);
                                }
                                // Clear message between two light clients
                                else if (!isSenderHeavy && !isTargetHeavy) {
                                    outputs[targetIndex].println("[Private] <" + userName + "> " + privateMessage);
                                }
                                // heavy -> light not possible
                                else if (isSenderHeavy && !isTargetHeavy) {
                                    outputs[targetIndex].println("[X] - You cannot read this message because you are a Light Client");
                                }
                                // Light -> Heavy yes
                                else {
                                    outputs[targetIndex].println("[Private] <" + userName + "> " + privateMessage);
                                }
                                output.println("[Private to " + targetUser + "] " + privateMessage);
                            }
                        }
                    }
                }
            }

            case "/sendFileTo", "/sendFileC" -> {
                if(!isHeavyClient){
                    output.println("[X] - You are not allowed to send file because you are a telnet client");
                }
            }

            case "/sendAll" -> {
                String fullMessage = "<" + userName + "> " + content;
                broadcastMessage(fullMessage);
            }
            case "/sendAllC" -> {
                if (content.isEmpty()) {
                    output.println("[X] - Usage: /sendAllC <base64(cipherDES(message))>");
                } else {
                    broadcastEncryptedMessage(userName, content);
                }
            }
            default -> {
                output.println("[X] - Unknown command: " + command);
            }
        }
    }

    /**
     * Send all the message to the user (between heavy client only because encrypt)
     * @param sender The sender of the message
     * @param encryptedMessage The encrypted message
     */
    private void broadcastEncryptedMessage(String sender, String encryptedMessage) {
        for (int i = 0; i < NBUSERSMAX; i++) {
            PrintStream output = outputs[i];
            if (output != null) {
                if (isHeavyClientMap.getOrDefault(userNames[i], false)) {
                    output.println("/C " + sender + " " + encryptedMessage);
                } else {
                    output.println("[X] - You cannot read this message because you are a Light Client");
                }
            }
        }
    }


    private static int findUserIndex(String name) {
        for (int i = 0; i < NBUSERSMAX; i++) {
            if (userNames[i].equalsIgnoreCase(name)) {
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

                if (message.startsWith("<SYSTEM> REGISTRATION PUBLICKEY ")) {
                    handlePublicKeyRegistration(userName, message);
                }
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
                System.out.println("[+] - " + userName + " disconnected");
                outputs[userIndex] = null;
                userNames[userIndex] = null;
                nbUsers--;

                broadcastMessage("\n[-] - " + userName + " left the chat");
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