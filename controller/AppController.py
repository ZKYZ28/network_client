from net.UnicastConnection import *
from model.Protocol import *
from tools.HashManager import *
from net.ClientThread import *
import traceback
import os.path

class AppController:
    def __init__(self, parser):
        self.parser = parser
        self.connection = UnicastConnection()
        self.hashmanager = HashManager()
        self.client_thread = None
        self.window_controller = None
        self.current_salt = None
        self.current_domain = None

    def ssl_ca_path(self, ca_path):
        self.connection.set_ca_path(ca_path)

    def set_window_controller(self, window_controller):
        self.window_controller = window_controller


    def on_connect(self, host, port, login, passw, tls, register=False):
        print("[AppController::on_connect]")
        try:
            if not self.connection.is_connected:
                print("[AppController::on_connect] connecting ... calling UnicastConnection::connect")
                self.connect(host, port, tls)
            line = self.connection.read_line()
            print(f"[AppController::on_connect] Received : '{line}'")
            message_id = self.parser.parse(line, False)
            if message_id == Protocol.PARSE_HELLO:
                tokens = self.parser.parse_HELLO(line)
                if register == True:
                    if self.manage_register(login, passw) == True:
                        self.window_controller.switch_connected_mode()
                        self.client_thread = ClientThread(self, self.connection, self.parser)
                        self.client_thread.start()
                    else:
                        self.show_message("Register failed : check if username is available", True)
                        self.connection.close()
                else:
                    if self.manage_connect(tokens[0], tokens[1], login, passw) == True:
                        self.window_controller.switch_connected_mode()
                        self.client_thread = ClientThread(self, self.connection, self.parser)
                        self.client_thread.start()
                    else:
                        self.show_message("Connection failed : check your credentials", True)
                        self.connection.close()
        except Exception as ex:
            print(ex)
            traceback.print_exc()

    def manage_connect(self, domain, challenge, login, passw):
        print("[AppController::manage_connect]")
        try:
            self.connection.send_message(self.parser.build_CONNECT(login))
            line = self.connection.read_line()
            print(f"[AppController::manage_connect] Received : '{line}'")
            message_id = self.parser.parse(line, False)
            if message_id == Protocol.PARSE_PARAM:
                tokens = self.parser.parse_PARAM(line)
                sha3hex = self.hashmanager.compute_sha3hex(passw, tokens[1], int(tokens[0]), challenge)
                self.connection.send_message(self.parser.build_CONFIRM(sha3hex))
                return self.is_ok()
            else:
                return False
        except Exception as ex:
            print(ex)
            traceback.print_exc()
            return False

    def manage_register(self, login, passw):
        print("[AppController::manager_register]")
        try:
            bhash = self.hashmanager.compute_bcrypt2(passw)
            self.connection.send_message(self.parser.build_REGISTER(login, self.hashmanager.salt_length(), bhash))
            return self.is_ok()

        except Exception as ex:
            print(ex)
            traceback.print_exc()
            return False
    
    def is_ok(self):
        try:
            line = self.connection.read_line()
            message_id = self.parser.parse(line, False)
            return (message_id == self.parser.PARSE_OK)

        except Exception as ex:
            print(ex)
            traceback.print_exc()
            return False

    def on_quit(self):
        if self.connection.is_connected:
            if self.client_thread != None:
                self.client_thread.on_quit()
                self.client_thread.stop_loop()
            self.connection.send_message(self.parser.build_DISCONNECT())
            
    def on_send(self, message):
        if self.connection.is_connected:
            self.connection.send_message(self.parser.build_MSG(message))
            self.new_message(None, message)
        else:
            self.show_message("Not connected !", True)
            
    def on_follow(self, follow):
        if self.connection.is_connected:
            self.connection.send_message(self.parser.build_FOLLOW(follow))
        else:
            self.show_message("Not connected !", True)

    def new_message(self, sender, message):
        if sender != None:
            self.window_controller.add_message(f"[{sender}] {message}", True)
        else:
            self.window_controller.add_message(f"[me] {message}", False)

    def show_message(self,message, is_error):
        self.window_controller.show_message(message, is_error)

    def connect(self, host, port, tls):
        try:
            self.connection.connect(host, port, tls)
            if tls and UnicastConnection.STRICT_SSL_VALIDATION:
                self.show_message(self.connection.ssl_info, False)
            elif tls and not UnicastConnection.STRICT_SSL_VALIDATION:
                self.show_message("SSL/TLS enabled, but certificate NOT checked !", False)
            else:
                self.show_message("No SSL connection", False)

        except Exception as ex:
            self.show_message(f"Error during connection !\n{ex}", True)
            self.connection = UnicastConnection()
