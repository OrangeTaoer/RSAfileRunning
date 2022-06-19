import platform

import PyQt5
from Crypto.PublicKey import RSA
from PyQt5.QtWidgets import QMainWindow
from PyQt5.uic.properties import QtWidgets

import en_decrypt
from file_RSA import Ui_Form
import sys


class mainFirm(QMainWindow,Ui_Form):
    def __init__(self):
        super().__init__()
        self.setupUi(self)
    def generate_key(self):
        print("generate key")
        code = "OrangeTao,RSA,generate key"
        # 生成 2048 位的 RSA 密钥
        key = RSA.generate(2048)
        encrypted_key = key.exportKey(passphrase=code,
                                      pkcs=8,
                                      protection="scryptAndAES128-CBC")
        # 生成私钥
        self.private_key.setText(str(encrypted_key, encoding="utf-8"))
        with open("rsa_private.key", "wb") as f:
            f.write(encrypted_key)
        # 生成公钥
        self.public_key.setText(
            str(key.publickey().exportKey(), encoding="utf-8"))
        with open("rsa_public.key", "wb") as f:
            f.write(key.publickey().exportKey())
        pass

    def apply_en_de(self):
        print("apply")
        systemtype = platform.system()
        if systemtype == "Windows":
            filepathvalue = self.filepath.toPlainText().replace("file:///", "")
        else:
            filepathvalue = self.filepath.toPlainText().replace("file://", "")
        if filepathvalue:
            # 解密按钮值(True&False)
            decryptionvalue = self.decryption.isChecked()
            if str(decryptionvalue) == "True":
                destatus = en_decrypt.Descrypt(filepathvalue)
                self.public_key.setText(destatus)
            else:
                enstatus = en_decrypt.Encrypt(filepathvalue)
                self.private_key.setText(enstatus)
        pass

if __name__ == "__main__":
    import sys

    Process = PyQt5.QtWidgets.QApplication(sys.argv)
    Ui_Window = mainFirm()
    Ui_Window.show()
    sys.exit(Process.exec_())