import hashlib
import os
import os.path
import base64
from Crypto import Random
from Crypto.Cipher import AES

class Encode:
    def __init__(self, file_name):
        self.text       = ""
        self.enc_txt    = ""
        self. filename  = file_name
        
    def encode(self, filename):
        with open(filename, "r", encoding="utf8", errors="ignore") as f:
            lines_list  = f.readlines()
            for lines in lines_list:
                self.text += lines
            self.text   = self.text.encode()
        with open(filename, "w") as f:
            f.write(str(base64.b64encode(self.text)))
            
class Encryptor:
    def __init__(self, keyx, file_name, bypassVM, EXT):
        self.bypassVM   = bypassVM
        self.plainkey   = keyx
        self.keyx       = keyx 
        self.file_name  = file_name
        self.EXT        = EXT
        
    def pad(self, s):
        return s + b"\0" * (AES.block_size - len(s) % AES.block_size)
    
    def encrypt(self, message, keyx, key_size=256):
        message         = self.pad(message)
        iv              = Random.new().read(AES.block_size)
        cipher          = AES.new(keyx, AES.MODE_CBC, iv)
        return iv + cipher.encrypt(message)
    
    def encrypt_file(self, file_name, EXT):
        with open(file_name, "rb") as fo:
            plaintext   = fo.read()
        enc             = self.encrypt(plaintext, self.keyx)
        with open(file_name + "." + self.EXT , "wb") as fo : 
            fo.write(enc)
        os.remove(file_name) 
         
    
    def decrypt(self, ciphertext, keyx, EXT):
        iv              = ciphertext[:AES.block_size]
        cipher          = AES.new(keyx, AES.MODE_CBC, iv)
        plaintext       = cipher.decrypt(ciphertext[AES.block_size:])
        return plaintext.rstrip(b"\0")
    
    def decrypt_file(self, file_name, EXT):
        with open(file_name, "rb") as fo:
            ciphertext  = fo.read()
        dec             = self.decrypt(ciphertext, self.keyx, self.EXT)
        A               = len(self.EXT)
        with open(file_name[:-A], "wb") as fo:
            fo.write(dec)
        os.remove(file_name)
if __name__ == '__main__':
    banner = '''
        #####################################
        #-----------FGN MADE DIS------------#
        #####################################
    '''
    print(banner)
    key             = input("[?] Enter Key              : ")
    file_name       = input("[?] Enter File Name        : ")
    bypassVM        = input("[?] Want to BypassVM (y/n) : ")
    EXT             = input("[?] Extension file         : ")
    fin             = file_name +'.' + EXT
    if len(EXT) == 0 or len(key) == 0:
        print("Please check your key, or extension")
        exit()
    else:
        pass
    bypassVM        = bypassVM.lower()
    keyx            = hashlib.sha256(key.encode('utf-8')).digest()
    test            = Encryptor(keyx, file_name, bypassVM, EXT) 
    encd            = Encode(file_name)
    
    option      = '''
[1] Encrypt file
[2] Decrypt file
[3] B64 + AES
[+]  : '''
    choice = int(input(option))
    if choice == 1:
        test.encrypt_file(file_name, EXT)
        print(f'''
+#---------------------------------#+ [X] ENCRYPTION INFO [X] +#---------------------------------#+
|[?] Og name        = {file_name}
|[?] Key            = {key}      
|[?] SHA256 Key     = {keyx}            
|[?] EXT            = {EXT}
|[?] File Name      = {fin}            
+-------------------------------------------------------------------------------------------------+
    ''')     
    if choice == 2:
        test.decrypt_file(file_name, EXT)
        finx    = file_name.rstrip('.' + EXT)
        print(f'''
+#---------------------------------#+ [X] DECRYPTION INFO [X] +#---------------------------------#+
|[?] Encrypted name= {file_name}
|[?] Key           = {key}      
|[?] SHA256 Key    = {keyx}            
|[?] EXT           = {EXT}
|[?] File Name     = {finx}            
+-------------------------------------------------------------------------------------------------+
    ''')
    if choice == 3:
        print('''[+] ENCODING USING BASE 64''')
        encd.encode(file_name)
        print('''[+] ENCRYPTING USING AES''')        
        test.encrypt_file(file_name, EXT)
        print(f'''
+#---------------------------------#+ [X] ENCRYPTION INFO [X] +#---------------------------------#+
|[?] Encrypted name= {file_name}
|[?] Key           = {key}      
|[?] SHA256 Key    = {keyx}            
|[?] EXT           = {EXT}
|[?] File Name     = {fin}
|[?] B64           = True            
+-------------------------------------------------------------------------------------------------+''')
    else:
        exit()
    
#`7MMAAAYMM       .g8AAAbgd       `7MN.  `7MF'     `7MMAAAYMM     `7MMF'   `7MF'     `7MMAAAYMM      `7MMAAAMq.                                   
# MM    `7      .dP'     `M        MMN.    M        MM    `7        `MA     ,V        MM    `7        MM   `MM.                                   
# MM   d        dM'       `        M YMb   M        MM   d           VM:   ,V         MM   d          MM   ,M9       .d*AAbg.  .d**AA.  .d*AAbg.  
# MMmmMM        MM                 M  `MN. M        MMmmMM            MM.  M'         MMmmMM          MMmmdM9       6MP    Mb 6MP    Mb 6MP    Mb 
# MM   Y  ,     MM.    `7MMF'      M   `MM.M        MM   Y  ,         `MM A'          MM   Y  ,       MM  YM.       YMb    MM YMb    MM YMb    MM 
# MM     ,M     `Mb.     MM        M     YMM        MM     ,M          :MM;           MM     ,M       MM   `Mb.      `MbmmdM9  `MbmmdM9  `MbmmdM9 
#.JMMmmmmMMM      `bmmmdP'         ML'    'Y'     'JMMmmmmMMM;'        'VF'         'JMMmmmmMMM .    JMML   .JMM'      '  .M'       .M'       .M' 
#                                                                                                                       .d9       .d9       .d9   
#                                                                                                                     m''       m''       m''     
