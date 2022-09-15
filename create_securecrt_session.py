# $language = "Python3"
# $interface = "1.0"

import virl2_client
import os
import sys
import platform
from Crypto.Hash import SHA256
from Crypto.Cipher import AES, Blowfish

cml_server = '192.168.1.246'
username = 'admin'
password = 'vucoki@3100ca25'

##Password encrypt from https://github.com/HyperSine/how-does-SecureCRT-encrypt-password
####thanks :D
class SecureCRTCryptoV2:

    def __init__(self, ConfigPassphrase: str = ''):
        '''
        Initialize SecureCRTCryptoV2 object.
        Args:
            ConfigPassphrase: The config passphrase that SecureCRT uses. Leave it empty if config passphrase is not set.
        '''
        self.IV = b'\x00' * AES.block_size
        self.Key = SHA256.new(ConfigPassphrase.encode('utf-8')).digest()

    def Encrypt(self, Plaintext: str):
        '''
        Encrypt plaintext and return corresponding ciphertext.
        Args:
            Plaintext: A string that will be encrypted.
        Returns:
            Hexlified ciphertext string.
        '''
        plain_bytes = Plaintext.encode('utf-8')
        if len(plain_bytes) > 0xffffffff:
            raise OverflowError('Plaintext is too long.')

        plain_bytes = len(plain_bytes).to_bytes(4, 'little') + plain_bytes + SHA256.new(plain_bytes).digest()
        padded_plain_bytes = plain_bytes +os.urandom(AES.block_size - len(plain_bytes) % AES.block_size)
        cipher = AES.new(self.Key, AES.MODE_CBC, iv=self.IV)
        return cipher.encrypt(padded_plain_bytes).hex()

def Main():
    configpassphrase = ''
    # cml_server = crt.Dialog.Prompt("Enter CML Server", "Login", "", False)
    # username = crt.Dialog.Prompt("Enter username for " + cml_server, "Login", "", False)
    # password = crt.Dialog.Prompt("Enter password for "+ cml_server, "Login", "", True)

    cml_conn = virl2_client.ClientLibrary(cml_server, username, password, ssl_verify=False)
    all_labs = cml_conn.all_labs()
    for lab in all_labs:
        for node in lab.nodes():
            new_session = crt.OpenSessionConfiguration()
            new_session.SetOption("Hostname", cml_server)
            new_session.SetOption("Username", username)
            password_encrypt = SecureCRTCryptoV2(configpassphrase).Encrypt(password)
            # new_session.SetOption("Password", password_encrypt)
            # new_session.SetOption("Password V2", '02:'+'70a6c2fc7cc45a2f61cf5d46326458751164dfc090f3a44ca9b01a4b77048202e5b5ece11899bccddd471aa0da2f912d95afbe1780b4a6902f61b68327326c86')
            new_session.SetOption("Password V2", '02:'+password_encrypt)
            new_session.SetOption("Protocol Name", "SSH2")
            new_session.SetOption("Session Password Saved", 1)
            new_session.SetOption("Use Login Script", 1)
            #login_script = '0onsoles>open /'+lab.title+'/'+node.label+'/0'
            # new_session.SetOption("Login Script V3", "02:2080da2028a5146d74178187b25d57bd11d87f875557ff2cd7ccf0d0906c2434785650896c32f1855ac5d6583ba472a0db7a715402d4c6a45f8893b9ba9829652e9b3de6309d4b874c0aa75bd98dac5e")
            new_session.SetOption("Mac Use Shell Command", 1)
            new_session.SetOption("Mac Shell Command", 'open /'+lab.title+'/'+node.label+'/0')

            new_session.Save(str(lab.title).replace(" ","_").replace(":","_")+'/'+node.label)

    #
    # crt.Dialog.MessageBox(
    #     "sys.version_info:\r\n{}\r\n\r\nsys.version:\r\n{}\r\n\r\nsys.hexversion:\r\n{}\r\n\r\nplatform.python_version:\r\n{}".format(
    #         sys.version_info,
    #         sys.version,
    #         sys.hexversion,
    #         platform.python_version()))

Main()
