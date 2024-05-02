# dcpm_huoban.py

import copy
from datetime import datetime
import string
import random
import secrets
import hashlib


def hash_password(password, salt):
    """Hash a password with a salt."""
    hasher = hashlib.sha256()
    password_salt_combo = password + salt
    hasher.update(password_salt_combo.encode("utf-8"))
    return hasher.hexdigest()


def generate_salt(length=16):
    """Generate a random salt."""
    return secrets.token_hex(length)


class Message:
    def __init__(self, user, text):
        self.user = user
        self.text = text
        self.time = datetime.now()


class User:
    def __init__(self, name, password):
        self.name = name
        self.password = password
        self.is_admin = False


class HuoBanMessageBoard:
    def __init__(self):
        self.messages = []
        self.users = {}
        self.privilege_codes = {
            "debug": self.debug_mode,
            "admin_mode": self.admin_mode,
        }

    def register_user(self, name, password):
        if name in self.users:
            raise ValueError("Username already exists")
        user = User(name, password)
        self.users[name] = user
        return user

    def post_message(self, user, text):
        message = Message(user, text)
        self.messages.append(message)

    def view_messages(self):
        return [(message.user.name, message.text) for message in self.messages]

    def enter_privilege_code(self, code):
        if code in self.privilege_codes:
            self.privilege_codes[code]()

    def debug_mode(self):
        for user in self.users.values():
            print(user.__dict__)

    def admin_mode(self):
        for user in self.users.values():
            user.is_admin = True


# 定义管理员模式
class Admin:
    def __init__(self, board):
        self.board = board

    def get_users(self):
        return list(self.board.users.keys())

    def delete_user(self, username):
        if username in self.board.users:
            del self.board.users[username]
        else:
            print("User does not exist.")


# 权限钩子
class PrivilegeHook:
    @staticmethod
    def add_privilege(board, code, method):
        board.privilege_codes[code] = method

    @staticmethod
    def remove_privilege(board, code):
        if code in board.privilege_codes:
            del board.privilege_codes[code]


# 直通钩子
class PassThroughHook:
    @staticmethod
    def debug_data(board):
        return board.__dict__

    @staticmethod
    def modify_data(board, attribute, value):
        setattr(board, attribute, value)


# 沙箱钩子
class SandboxHook:
    def __init__(self, board):
        self.sandbox = copy.deepcopy(board)

    def simulate_post_message(self, user, text):
        if user.name in self.sandbox.users:
            message = Message(user, text)
            self.sandbox.messages.append(message)
            return True
        return False

    def view_sandbox_data(self):
        return self.sandbox.__dict__


# 动态元钩子
class MetaHook:
    @staticmethod
    def create_class(class_name, base_classes=None, attributes=None):
        base_classes = base_classes or (object,)
        attributes = attributes or {}
        new_class = type(class_name, base_classes, attributes)
        return new_class

    @staticmethod
    def add_attribute(obj, attr_name, value):
        setattr(obj, attr_name, value)

    @staticmethod
    def remove_attribute(obj, attr_name):
        if hasattr(obj, attr_name):
            delattr(obj, attr_name)

    @staticmethod
    def add_method(obj, method_name, method):
        setattr(obj, method_name, method.__get__(obj, obj.__class__))

    @staticmethod
    def remove_method(obj, method_name):
        if hasattr(obj, method_name):
            delattr(obj, method_name)


# 静态钩子
class StaticHook:
    events = {}
    configurations = {}

    @staticmethod
    def register_event(event_name, callback):
        if event_name not in StaticHook.events:
            StaticHook.events[event_name] = []
        StaticHook.events[event_name].append(callback)

    @staticmethod
    def trigger_event(event_name, *args, **kwargs):
        if event_name in StaticHook.events:
            for callback in StaticHook.events[event_name]:
                callback(*args, **kwargs)

    @staticmethod
    def configure(key, value):
        StaticHook.configurations[key] = value

    @staticmethod
    def get_configuration(key):
        return StaticHook.configurations.get(key)

    @staticmethod
    def list_registered_events():
        return list(StaticHook.events.keys())


# 安全补丁

# Apply the security patches on the loaded code


# Modify the User class to store hashed passwords and salt
class SecureUser(User):
    def __init__(self, name, password):
        super().__init__(name, password)
        self.salt = generate_salt()
        self.hashed_password = hash_password(password, self.salt)

    def verify_password(self, password):
        return self.hashed_password == hash_password(password, self.salt)


# Modify the HuoBanMessageBoard class
class SecureHuoBanMessageBoard(HuoBanMessageBoard):
    def register_user(self, name, password):
        if name in self.users:
            raise ValueError("Username already exists")
        user = SecureUser(name, password)
        self.users[name] = user
        return user

    # Secure privilege code method
    def enter_privilege_code(self, user, password, code):
        if (
            user.verify_password(password)
            and user.is_admin
            and code in self.privilege_codes
        ):
            self.privilege_codes[code]()

    # Only admin can turn others into admin
    def admin_mode(self, user, target_user):
        if user.is_admin:
            target_user.is_admin = True


# Create a secure hook verifier
class SecureHookVerifier:
    def __init__(self):
        self.authorized_users = []

    def authorize_user(self, user):
        if user.is_admin:
            self.authorized_users.append(user.name)

    def is_authorized(self, user):
        return user.name in self.authorized_users


# Secure the hooks with the verifier
class SecurePassThroughHook(PassThroughHook):
    def __init__(self, verifier):
        self.verifier = verifier

    def debug_data(self, user, board):
        if self.verifier.is_authorized(user):
            return super().debug_data(board)
        return "Unauthorized"

    def modify_data(self, user, board, key, value):
        if self.verifier.is_authorized(user):
            super().modify_data(board, key, value)


# ... (Other hooks can be secured in a similar manner)

# This is a basic implementation and might need further adjustments and testing in a real-world scenario.
# Also, additional security measures like logging, monitoring, rate limiting, etc. can be added for further hardening.


# 扩展

# Extend the existing SecureUser and SecureHuoBanMessageBoard classes


class ExtendedUser(SecureUser):
    def __init__(self, name, password):
        super().__init__(name, password)
        self.profile = {"avatar": None, "bio": ""}
        self.logged_in = False

    def login(self, password):
        if self.verify_password(password):
            self.logged_in = True
            return True
        return False

    def logout(self):
        self.logged_in = False

    def update_profile(self, avatar=None, bio=None):
        if avatar:
            self.profile["avatar"] = avatar
        if bio:
            self.profile["bio"] = bio


class ExtendedHuoBanMessageBoard(SecureHuoBanMessageBoard):
    def __init__(self):
        super().__init__()
        self.private_messages = {}
        self.likes = {}
        self.comments = {}
        self.reports = []
        self.pinned_messages = []

    def send_private_message(self, sender, receiver, text):
        message = Message(sender, text)
        if receiver.name not in self.private_messages:
            self.private_messages[receiver.name] = []
        self.private_messages[receiver.name].append(message)

    def like_message(self, user, message):
        if message not in self.likes:
            self.likes[message] = []
        if user not in self.likes[message]:
            self.likes[message].append(user)

    def comment_on_message(self, user, message, comment_text):
        comment = Message(user, comment_text)
        if message not in self.comments:
            self.comments[message] = []
        self.comments[message].append(comment)

    def report_message(self, user, message, reason):
        self.reports.append({"reporter": user, "message": message, "reason": reason})

    def pin_message(self, message):
        if message not in self.pinned_messages:
            self.pinned_messages.append(message)

    def blacklist_user(self, user):
        user.is_blacklisted = True

    # ... More functions can be added for other features


# This implementation provides the basic structure for the functionalities.
# Further refinements and additions are possible based on specific requirements.


class SimulatedTerminal:
    def __init__(self):
        self.commands = {
            "echo": self.echo,
            "view_messages": self.view_messages,
            # ... more commands can be added
        }

    def parse_and_execute(self, command_str):
        # UNIX style: command -a
        if " -" in command_str:
            command, arg = command_str.split(" -", 1)
            arg = "-" + arg

        # DOS style: COMMAND /a
        elif " /" in command_str:
            command, arg = command_str.split(" /", 1)
            arg = "/" + arg

        # IRC style: /command argv
        elif command_str.startswith("/"):
            parts = command_str[1:].split(" ", 1)
            command = parts[0]
            arg = parts[1] if len(parts) > 1 else None

        # Default style: command argv
        else:
            parts = command_str.split(" ", 1)
            command = parts[0]
            arg = parts[1] if len(parts) > 1 else None

        # Execute the parsed command
        if command in self.commands:
            return self.commands[command](arg)
        else:
            return f"Command '{command}' not found!"

    def echo(self, arg):
        return arg

    def view_messages(self, arg):
        # This is just a placeholder and can be integrated with the real message board
        return "Here are the messages!"

    # ... more command methods can be added


# Test the simulated terminal
terminal = SimulatedTerminal()
test_command_output = terminal.parse_and_execute("echo -Hello, World!")
test_command_output


class DecryptionChallenge:
    def __init__(self):
        self.alphabet = string.ascii_lowercase
        self.key = "".join(random.sample(self.alphabet, len(self.alphabet)))
        self.max_attempts = 3
        self.attempts = 0

    def encrypt(self, plaintext):
        table = str.maketrans(self.alphabet, self.key)
        return plaintext.translate(table)

    def decrypt(self, ciphertext, user_key):
        table = str.maketrans(self.key, self.alphabet)
        return ciphertext.translate(table)

    def challenge_user(self, plaintext):
        encrypted = self.encrypt(plaintext)
        print(f"Encrypted Text: {encrypted}")

        while self.attempts < self.max_attempts:
            user_key = input("Enter your decryption key: ")
            decrypted = self.decrypt(encrypted, user_key)

            if decrypted == plaintext:
                return "Congratulations! You decrypted the message successfully!"
            else:
                self.attempts += 1
                remaining = self.max_attempts - self.attempts
                if remaining > 0:
                    print(f"Incorrect! {remaining} attempts remaining.")
                else:
                    return "Sorry, you failed the challenge!"


# Initialize and test the decryption challenge
decryption_challenge = DecryptionChallenge()
# We will call this function later in an interactive session to get user input
# For now, we will just return the encrypted version of a test message
encrypted_test_message = decryption_challenge.encrypt("hello")
encrypted_test_message


class HackerTerminal(SimulatedTerminal):
    def __init__(self):
        super().__init__()
        self.commands["decryption_challenge"] = self.start_decryption_challenge
        self.decryption_challenge = DecryptionChallenge()

    def start_decryption_challenge(self, arg):
        plaintext = (
            "hello"  # For simplicity, we use a fixed plaintext for the challenge
        )
        return self.decryption_challenge.challenge_user(plaintext)


# Test the integrated terminal with the decryption challenge
# For demonstration purposes, we will simulate user input within the code
hacker_terminal = HackerTerminal()
challenge_output = hacker_terminal.parse_and_execute("decryption_challenge")
challenge_output


class CodeCrackChallenge:
    def __init__(self):
        self.code = str(random.randint(1000, 9999))
        self.max_attempts = 3
        self.attempts = 0

    def challenge_user(self):
        print("Crack the 4-digit code!")

        while self.attempts < self.max_attempts:
            guess = input("Enter your guess: ")

            if guess == self.code:
                return "Congratulations! You cracked the code!"
            else:
                self.attempts += 1
                remaining = self.max_attempts - self.attempts
                if remaining > 0:
                    print(f"Incorrect! {remaining} attempts remaining.")
                else:
                    return "Sorry, you failed the challenge!"


# Integrate the code crack challenge into the hacker terminal
class ExtendedHackerTerminal(HackerTerminal):
    def __init__(self):
        super().__init__()
        self.commands["code_crack_challenge"] = self.start_code_crack_challenge
        self.code_crack_challenge = CodeCrackChallenge()

    def start_code_crack_challenge(self, arg):
        return self.code_crack_challenge.challenge_user()


# Since we can't run interactive input here,
# the function is provided for demonstration and can be tested in a local environment.


class VirtualNetwork:
    def __init__(self):
        self.computers = ["PC-001", "PC-002", "PC-003", "SERVER-001"]
        self.infiltrated = []

    def show_network(self):
        return "Available computers: " + ", ".join(self.computers)

    def infiltrate(self, target):
        if target in self.computers:
            self.infiltrated.append(target)
            return f"Infiltrated {target}!"
        else:
            return f"{target} not found on the network!"


# Integrate the virtual network into the hacker terminal
class FinalHackerTerminal(ExtendedHackerTerminal):
    def __init__(self):
        super().__init__()
        self.commands["show_network"] = self.display_network
        self.commands["infiltrate"] = self.perform_infiltration
        self.virtual_network = VirtualNetwork()

    def display_network(self, arg):
        return self.virtual_network.show_network()

    def perform_infiltration(self, target):
        return self.virtual_network.infiltrate(target)


# Test the virtual network functionality
hacker_terminal_final = FinalHackerTerminal()
network_output = hacker_terminal_final.parse_and_execute("show_network")
network_output


class LogAnalysisChallenge:
    def __init__(self):
        self.logs = []
        self.suspicious_ips = ["192.168.1.101", "10.0.0.5"]
        self.generate_logs()

    def generate_logs(self):
        ips = ["192.168.1.100", "192.168.1.101", "10.0.0.1", "10.0.0.2", "10.0.0.5"]
        for _ in range(50):
            ip = random.choice(ips)
            self.logs.append(f"Connection attempt from {ip}")

    def show_logs(self):
        return "\n".join(self.logs)

    def analyze(self, ip):
        if ip in self.suspicious_ips:
            return f"{ip} is a suspicious IP!"
        else:
            return f"{ip} is not suspicious."


# Integrate the log analysis challenge into the hacker terminal
class LogAnalysisHackerTerminal(FinalHackerTerminal):
    def __init__(self):
        super().__init__()
        self.commands["show_logs"] = self.display_logs
        self.commands["analyze_ip"] = self.perform_analysis
        self.log_analysis = LogAnalysisChallenge()

    def display_logs(self, arg):
        return self.log_analysis.show_logs()

    def perform_analysis(self, ip):
        return self.log_analysis.analyze(ip)


# Test the log analysis functionality
log_terminal = LogAnalysisHackerTerminal()
logs_output = log_terminal.parse_and_execute("show_logs")
logs_output.split("\n")[:10]  # Displaying first 10 log entries for brevity


class TextSteganography:
    def __init__(self):
        self.delimiter = "%%"

    def hide_message(self, main_text, secret_message):
        return main_text + self.delimiter + secret_message

    def retrieve_message(self, stego_text):
        parts = stego_text.split(self.delimiter)
        if len(parts) > 1:
            return parts[1]
        else:
            return "No hidden message found."


# Integrate the text steganography into the hacker terminal
class SteganoHackerTerminal(LogAnalysisHackerTerminal):
    def __init__(self):
        super().__init__()
        self.commands["hide_message"] = self.hide_secret_message
        self.commands["retrieve_message"] = self.get_hidden_message
        self.steganography = TextSteganography()

    def hide_secret_message(self, args):
        main_text, secret_message = args.split("::")
        return self.steganography.hide_message(main_text, secret_message)

    def get_hidden_message(self, stego_text):
        return self.steganography.retrieve_message(stego_text)


# Test the text steganography functionality
stegano_terminal = SteganoHackerTerminal()
hidden_message = stegano_terminal.parse_and_execute(
    "hide_message This is a normal text.::This is a secret!"
)
hidden_message


class ChatSimulator:
    def __init__(self):
        self.terminal = SteganoHackerTerminal()
        self.chat_history = []

    def send_message(self, user, message):
        if message.startswith("/"):
            response = self.terminal.parse_and_execute(message[1:])
            self.chat_history.append(("System", response))
        else:
            self.chat_history.append((user, message))

    def display_chat(self):
        return "\n".join([f"{user}: {message}" for user, message in self.chat_history])


# Test the chat simulator with terminal integration
chat = ChatSimulator()
chat.send_message("User", "Hello everyone!")
chat.send_message("User", "/hide_message This is a public message.::This is a secret!")
chat.send_message("Alice", "Hey User!")
chat.send_message(
    "User", "/retrieve_message This is a public message.%%This is a secret!"
)
chat_display = chat.display_chat()
chat_display


class EnhancedHuoBanMessageBoard(ExtendedHuoBanMessageBoard):
    def __init__(self):
        super().__init__()
        self.chat_simulator = ChatSimulator()

    def post_message(self, user, text):
        super().post_message(user, text)
        # Execute command if the text starts with a "/"
        if text.startswith("/"):
            response = self.chat_simulator.terminal.parse_and_execute(text[1:])
            super().post_message("System", response)

    def display_board(self):
        messages = []
        for msg in self.messages:
            messages.append(f"{msg.user.name}: {msg.text}")
        return "\n".join(messages)


# Test the integrated message board with chat simulator functionality
"""
enhanced_board = EnhancedHuoBanMessageBoard()
enhanced_board.post_message(ExtendedUser("User", "password123"), "Hello everyone!")
enhanced_board.post_message(ExtendedUser("User", "password123"), "/hide_message Public text.::Hidden secret!")
enhanced_board.post_message(ExtendedUser("Alice", "alicepass"), "Hi User!")
enhanced_board.post_message(ExtendedUser("User", "password123"), "/retrieve_message Public text.%%Hidden secret!")
board_display = enhanced_board.display_board()
board_display
"""
# 测

# 注册用户
board = HuoBanMessageBoard()
alice = board.register_user("Alice", "password123")
bob = board.register_user("Bob", "password456")

# Alice 发布消息
board.post_message(alice, "Hello everyone!")
board.post_message(bob, "Hi Alice!")

# 查看消息
print(board.view_messages())

# 使用特权码
board.enter_privilege_code("debug")

# 使用管理员模式
admin = Admin(board)
print(admin.get_users())
admin.delete_user("Bob")
print(admin.get_users())


# 使用权限钩子
def secret_admin_mode():
    print("Secret Admin Mode Activated!")


PrivilegeHook.add_privilege(board, "secret_admin", secret_admin_mode)
board.enter_privilege_code("secret_admin")

# 使用直通钩子
print(PassThroughHook.debug_data(board))
PassThroughHook.modify_data(board, "messages", [])

# 使用沙箱钩子
sandbox = SandboxHook(board)
sandbox.simulate_post_message(alice, "This is a sandboxed message!")
print(sandbox.view_sandbox_data())

# 使用动态元钩子
NewClass = MetaHook.create_class("NewClass")
obj = NewClass()
MetaHook.add_attribute(obj, "attr", "value")
print(obj.attr)
MetaHook.remove_attribute(obj, "attr")

# 使用静态钩子

StaticHook.trigger_event("message_posted", alice, "This is a message!")
print(StaticHook.list_registered_events())
