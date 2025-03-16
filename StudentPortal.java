import java.util.*;

public class StudentPortal {
    private static Map<String, User> users = new HashMap<>();
    private static Map<String, OTP> otpStore = new HashMap<>();
    private static final int SHIFT = 3;
    private static final long OTP_VALIDITY = 5 * 60 * 1000;

    static class User {
        String username;
        String email;
        String encryptedPassword;

        public User(String username, String email, String encryptedPassword) {
            this.username = username;
            this.email = email;
            this.encryptedPassword = encryptedPassword;
        }
    }

    static class OTP {
        String code;
        long timestamp;

        public OTP(String code, long timestamp) {
            this.code = code;
            this.timestamp = timestamp;
        }
    }

    static class CaesarCipher {
        public static String encrypt(String plainText, int shift) {
            StringBuilder result = new StringBuilder();
            for (char c : plainText.toCharArray()) {
                if (Character.isLetter(c)) {
                    char base = Character.isLowerCase(c) ? 'a' : 'A';
                    c = (char) ((c - base + shift) % 26 + base);
                }
                result.append(c);
            }
            return result.toString();
        }

        public static String decrypt(String encryptedText, int shift) {
            StringBuilder result = new StringBuilder();
            for (char c : encryptedText.toCharArray()) {
                if (Character.isLetter(c)) {
                    char base = Character.isLowerCase(c) ? 'a' : 'A';
                    int originalPosition = (c - base - shift) % 26;
                    if (originalPosition < 0) {
                        originalPosition += 26;
                    }
                    c = (char) (originalPosition + base);
                }
                result.append(c);
            }
            return result.toString();
        }
    }

    private static void demonstrateDecryption(String username) {
        User user = users.get(username);
        if (user != null) {
            String decrypted = CaesarCipher.decrypt(user.encryptedPassword, SHIFT);
            System.out.println("\nDecryption Demonstration:");
            System.out.println("Encrypted: " + user.encryptedPassword);
            System.out.println("Decrypted: " + decrypted);
        }
    }

    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        while (true) {
            System.out.println("\nStudent Portal");
            System.out.println("1. Register");
            System.out.println("2. Login");
            System.out.println("3. Exit");
            System.out.print("Select option: ");
            
            String choice = scanner.nextLine();
            
            switch (choice) {
                case "1":
                    registerUser(scanner);
                    break;
                case "2":
                    loginUser(scanner);
                    break;
                case "3":
                    System.out.println("Exiting...");
                    scanner.close();
                    return;
                default:
                    System.out.println("Invalid option!");
            }
        }
    }

    private static void registerUser(Scanner scanner) {
        System.out.print("\nEnter username: ");
        String username = scanner.nextLine();
        
        if (users.containsKey(username)) {
            System.out.println("Username already exists!");
            return;
        }

        System.out.print("Enter email: ");
        String email = scanner.nextLine();
        System.out.print("Enter password: ");
        String password = scanner.nextLine();

        String encrypted = CaesarCipher.encrypt(password, SHIFT);
        users.put(username, new User(username, email, encrypted));
        System.out.println("Registration successful!");
    }

    private static void loginUser(Scanner scanner) {
        System.out.print("\nEnter username: ");
        String username = scanner.nextLine();
        System.out.print("Enter password: ");
        String password = scanner.nextLine();

        User user = users.get(username);
        if (user == null || !user.encryptedPassword.equals(CaesarCipher.encrypt(password, SHIFT))) {
            System.out.println("Invalid credentials!");
            return;
        }

        String otp = generateOTP();
        otpStore.put(username, new OTP(otp, System.currentTimeMillis()));
        System.out.println("OTP sent to your email (simulated): " + otp);

        System.out.print("Enter OTP: ");
        String inputOtp = scanner.nextLine();

        OTP storedOtp = otpStore.get(username);
        if (storedOtp == null || 
            !storedOtp.code.equals(inputOtp) || 
            (System.currentTimeMillis() - storedOtp.timestamp) > OTP_VALIDITY) {
            
            System.out.println("Invalid or expired OTP!");
            return;
        }

        // Remove OTP after successful validation
        otpStore.remove(username);
        System.out.println("\nLogin successful! Welcome " + username + "!");
        showDashboard(scanner, username);
    }

    private static void showDashboard(Scanner scanner, String username) {
        while (true) {
            System.out.println("\nDashboard");
            System.out.println("1. View Profile");
            System.out.println("2. Demonstrate Decryption");
            System.out.println("3. Logout");
            System.out.print("Select option: ");
            
            String choice = scanner.nextLine();
            
            switch (choice) {
                case "1":
                    viewProfile(username);
                    break;
                case "2":
                    demonstrateDecryption(username);
                    break;
                case "3":
                    return;
                default:
                    System.out.println("Invalid option!");
            }
        }
    }

    private static void viewProfile(String username) {
        User user = users.get(username);
        if (user == null) {
            System.out.println("User not found!");
            return;
        }
        System.out.println("\nProfile Details");
        System.out.println("Username: " + user.username);
        System.out.println("Email: " + user.email);
        System.out.println("Encrypted Password: " + user.encryptedPassword);
    }

    private static String generateOTP() {
        Random rand = new Random();
        return String.format("%06d", rand.nextInt(1000000));
    }
}