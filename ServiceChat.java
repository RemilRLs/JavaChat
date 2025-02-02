import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintStream;
import java.io.IOException;
import java.net.Socket;
import java.net.ServerSocket;

/**
 * Class to handle the chat service (server)
 * The service is going to handle multiple clients and send it to everyone connected
 */
public class ServiceChat extends Thread {
    private BufferedReader input;

    static final int NBUSERSMAX = 5;
    static int nbUsers = 0; // Number of connected users.
    private static final String[] userNames = new String[NBUSERSMAX];
    public static PrintStream[] outputs = new PrintStream[NBUSERSMAX];

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

            String chosenName = null;
            while (true) {
                tempOutput.println("[+] - Enter your name: ");
                chosenName = input.readLine();
                if (chosenName == null) {
                    tempOutput.println("[-] - Invalid name. Try again.");
                    continue;
                }

                chosenName = chosenName.trim();
                if (chosenName.isEmpty()) {
                    tempOutput.println("[-] - Name cannot be empty.");
                    continue;
                }

                synchronized (ServiceChat.class) {
                    if (isNicknameAlreadyUsed(chosenName)) {
                        tempOutput.println("[-] - Name already in use. Choose another.");
                    } else {
                        userIndex = -1;
                        for (int i = 0; i < NBUSERSMAX; i++) {
                            if (outputs[i] == null) {
                                userIndex = i;
                                break;
                            }
                        }
                        if (userIndex == -1) {
                            tempOutput.println("[-] - Server error. Try again later.");
                            socket.close();
                            return false;
                        }

                        userName = chosenName;
                        outputs[userIndex] = tempOutput;
                        userNames[userIndex] = userName;
                        nbUsers++;

                        tempOutput.println("[+] - Welcome " + userName + "!");
                        broadcastMessage("\n[+] - " + userName + " joined the chat!");

                        System.out.println("[+] - " + userName + " connected. Users: " + nbUsers);
                        return true;
                    }
                }
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

    /**
     * Main loop to read messages from the client and broadcast them
     */
    private void mainLoop() {
        try {
            String message;
            PrintStream currentOutput = outputs[userIndex];
            currentOutput.print("[>] Enter message: ");
            while ((message = input.readLine()) != null) {
                String fullMessage = "<" + userName + "> " + message;
                System.out.println("[Chat] " + fullMessage);
                broadcastMessage(fullMessage);
                currentOutput.print("[>] Enter message: ");
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