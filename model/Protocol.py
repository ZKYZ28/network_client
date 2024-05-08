import re

class Protocol:
    RX_DIGIT = r"[0-9]"
    RX_LETTER = r"[a-zA-Z]"
    RX_LETTER_DIGIT = r"" + RX_LETTER + "|" + RX_DIGIT
    RX_SYMBOL = r"[\x21-\x2f]|[\x3a-\x40]|[\x5B-\x60]"
    RX_CRLF = r"(\\x0d\\x0a){0,1}"
    RX_ROUND = r"(" + RX_DIGIT + "{2})"
    RX_PASSCHAR = r"[\x22-\xff]"
    RX_VISIBLE_CHARACTER = r"[\x20-\xff]"
    RX_INFORMATION_MESSAGE = r"((" + RX_VISIBLE_CHARACTER + "){0,200})" 
    RX_RANDOM = r"((" + RX_LETTER_DIGIT + "|" + RX_SYMBOL + "){22})"
    RX_BCRYPT_SALT = r"((" + RX_LETTER_DIGIT + "|" + RX_SYMBOL + "){22})"
    RX_ESP = r" "
    RX_DOMAIN = r"((" + RX_LETTER_DIGIT + "|\.){5,200})";
    RX_USERNAME = r"((" + RX_LETTER_DIGIT +"){5,20})"
    RX_USER_DOMAIN = r"(" + RX_USERNAME + "@" + RX_DOMAIN + ")"
    RX_MESSAGE = r"((" + RX_VISIBLE_CHARACTER + "){1,250})"

    RX_HELLO = r"HELLO" + RX_ESP + RX_DOMAIN + RX_ESP + RX_RANDOM + RX_CRLF
    RX_PARAM = r"PARAM" + RX_ESP + RX_ROUND + RX_ESP + RX_BCRYPT_SALT + RX_CRLF
    RX_MSGS = r"MSGS" + RX_ESP + RX_USER_DOMAIN + RX_ESP + RX_MESSAGE + RX_CRLF
    RX_OK = r"\+OK" + RX_INFORMATION_MESSAGE + RX_CRLF
    RX_ERR = r"-ERR" + RX_INFORMATION_MESSAGE + RX_CRLF 

    ALL_MESSAGES = [RX_HELLO, RX_PARAM, RX_OK, RX_ERR, RX_MSGS]
    PARSE_UNKNOWN = -1
    PARSE_HELLO = 0
    PARSE_PARAM = 1
    PARSE_OK = 2
    PARSE_ERR = 3
    PARSE_MSGS = 4

    CONNECT_MSG = "CONNECT <username>\r\n"
    REGISTER_MSG = "REGISTER <username> <salt_length> <bcrypt_hash>\r\n"
    CONFIRM_MSG = "CONFIRM <sha3hexstring>\r\n"
    MSG_MSG = "MSG <message>\r\n"
    FOLLOW_MSG = "FOLLOW <follow>\r\n"
    DISCONNECT_MSG = "DISCONNECT\r\n"

    def build_CONNECT(self, username):
        return Protocol.CONNECT_MSG.replace("<username>", username)

    def build_REGISTER(self, username, length, hash):
        return Protocol.REGISTER_MSG.replace("<username>", username).replace("<salt_length>", f"{length}").replace("<bcrypt_hash>", hash)

    def build_CONFIRM(self, sha3hex):
        return Protocol.CONFIRM_MSG.replace("<sha3hexstring>", sha3hex)

    def build_MSG(self, message):
        return Protocol.MSG_MSG.replace("<message>", message)

    def build_FOLLOW(self,follow):
        return Protocol.FOLLOW_MSG.replace("<follow>", follow)

    def build_DISCONNECT(self):
        return Protocol.DISCONNECT_MSG
    
    def parse_HELLO(self, message):
        if(self.parse(message, False) == Protocol.PARSE_HELLO):
            return self.get_elements_from_regex(message, Protocol.RX_HELLO, [1,3])
    
    def parse_PARAM(self, message):
        if(self.parse(message, False) == Protocol.PARSE_PARAM):
            return self.get_elements_from_regex(message, Protocol.RX_PARAM, [1,2])

    def parse_MSGS(self, message):
        if self.parse(message, False) == Protocol.PARSE_MSGS:
            return self.get_elements_from_regex(message, Protocol.RX_MSGS, [1,6])

    def get_elements_from_regex(self, message, rx, elements):
        result = []
        group_list = re.search(rx, message)
        if(group_list != None):
            for val in elements:
                result.append(group_list.group(val))
            return result
        else: 
            return None


    def parse(self, line, debug_enabled):
        for i in range(len(Protocol.ALL_MESSAGES)):
            if(re.match(Protocol.ALL_MESSAGES[i], line) != None):
                if(debug_enabled):
                    print(f"OK REGEXP: {Protocol.ALL_MESSAGES[i]}")
                return i
            else:
                if(debug_enabled):
                    print(f"KO REGEXP {Protocol.ALL_MESSAGES[i]}")
        return Protocol.PARSE_UNKNOWN

if __name__ == '__main__':
    protocol = Protocol()
    line = input("> ")
    while(line != ""):
        val = protocol.parse(line, True)
        v = protocol.get_elements_from_regex(line, Protocol.RX_MSGS, [1,6])
        print(f"Val = {v}")
        line = input("> ")