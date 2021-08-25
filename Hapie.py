#For Hashes,arguments and random_nums
import random
import sys
import hashlib
import binascii
import whirlpool
import codecs
import zlib
import base64
import bcrypt
from passlib.hash import lmhash
from passlib.hash import nthash
from passlib.hash import argon2
from Crypto.Hash import MD2
from Crypto.Hash import MD4
from argon2 import PasswordHasher
from passlib.hash import sha256_crypt
from passlib.hash import sha512_crypt
from passlib.hash import pbkdf2_sha256
from passlib.hash import pbkdf2_sha512
#For coloured text and progressbar
from rich import progress ,print


VERSION = '1.0.4'


_banner_list = [
rf'''
  _   _      _       ____     ____            U _____ u 
 |'| |'| U  /"\  u U|  _"\ uU|  _"\ u  ___    \| ___"|/ 
/| |_| |\ \/ _ \/  \| |_) |/\| |_) |/ |_"_|    |  _|"   
U|  _  |u / ___ \   |  __/   |  __/    | |     | |___   
 |_| |_| /_/   \_\  |_|      |_|     U/| |\u   |_____|  
 //   \\  \\    >>  ||>>_    ||>>_.-,_|___|_,-.<<   >>  
(_") ("_)(__)  (__)(__)__)  (__)__)\_)-' '-(_/(__) (__) [by Justaus3r]
                                                        [ver:{VERSION}]''',
rf'''
    )                               
 ( /(                               
 )\())    )               (     (   
((_)\  ( /(  `  )   `  )  )\   ))\  
 _((_) )(_)) /(/(   /(/( ((_) /((_) 
| || |((_)_ ((_)_\ ((_)_\ (_)(_))   
| __ |/ _` || '_ \)| '_ \)| |/ -_)  
|_||_|\__,_|| .__/ | .__/ |_|\___|  
            |_|    |_|            [by justaus3r]
                                  [ver:{VERSION}]''',
rf'''
   \\  //       ))    ))   wW  Ww       
   (o)(o)   /) (o0)-.(o0)-.(O)(O) wWw   
   ||  || (o)(O)| (_))| (_))(..)  (O)_  
   |(__)|  //\\ | .-' | .-'  ||  .' __) 
   /.--.\ |(__)||(    |(    _||_(  _)   
  -'    `-/,-. | \)    \)  (_/\_)`.__) [by justaus3r] 
         -'   '' (     (                [ver:{VERSION}]''',
rf'''
 _  _   __   ____  ____  __  ____ 
/ )( \ / _\ (  _ \(  _ \(  )(  __)
) __ (/    \ ) __/ ) __/ )(  ) _) 
\_)(_/\_/\_/(__)  (__)  (__)(____)[by justaus3r]
                                  [ver:{VERSION}]''',
rf'''
      ___           ___           ___           ___                       ___     
     /\__\         /\  \         /\  \         /\  \          ___        /\  \    
    /:/  /        /::\  \       /::\  \       /::\  \        /\  \      /::\  \   
   /:/__/        /:/\:\  \     /:/\:\  \     /:/\:\  \       \:\  \    /:/\:\  \  
  /::\  \ ___   /::\~\:\  \   /::\~\:\  \   /::\~\:\  \      /::\__\  /::\~\:\  \ 
 /:/\:\  /\__\ /:/\:\ \:\__\ /:/\:\ \:\__\ /:/\:\ \:\__\  __/:/\/__/ /:/\:\ \:\__\
 \/__\:\/:/  / \/__\:\/:/  / \/__\:\/:/  / \/__\:\/:/  / /\/:/  /    \:\~\:\ \/__/
      \::/  /       \::/  /       \::/  /       \::/  /  \::/__/      \:\ \:\__\  
      /:/  /        /:/  /         \/__/         \/__/    \:\__\       \:\ \/__/  
     /:/  /        /:/  /                                  \/__/        \:\__\    
     \/__/         \/__/                                                 \/__/ [by justaus3r]
                                                                               [ver:{VERSION}]''',  
rf'''
    __  __                  _    
   / / / /___ _____  ____  (_)__ 
  / /_/ / __ `/ __ \/ __ \/ / _ \
 / __  / /_/ / /_/ / /_/ / /  __/
/_/ /_/\__,_/ .___/ .___/_/\___/ [by justaus3r]
           /_/   /_/             [ver:{VERSION}]''',
rf'''
,--.  ,--.                      ,--.        
|  '--'  | ,--,--. ,---.  ,---. `--' ,---.  
|  .--.  |' ,-.  || .-. || .-. |,--.| .-. : 
|  |  |  |\ '-'  || '-' '| '-' '|  |\   --. 
`--'  `--' `--`--'|  |-' |  |-' `--' `----'[by justaus3r] 
                  `--'   `--'               [ver:{VERSION}]''',
rf'''
 __  __     ______     ______   ______   __     ______    
/\ \_\ \   /\  __ \   /\  == \ /\  == \ /\ \   /\  ___\   
\ \  __ \  \ \  __ \  \ \  _-/ \ \  _-/ \ \ \  \ \  __\   
 \ \_\ \_\  \ \_\ \_\  \ \_\    \ \_\    \ \_\  \ \_____\ 
  \/_/\/_/   \/_/\/_/   \/_/     \/_/     \/_/   \/_____/[by justaus3r]
                                                         [ver:{VERSION}]''',    
rf'''
 .-. .-.  .--.  ,---.  ,---.  ,-.,---.   
 | | | | / /\ \ | .-.\ | .-.\ |(|| .-'   
 | `-' |/ /__\ \| |-' )| |-' )(_)| `-.   
 | .-. ||  __  || |--' | |--' | || .-'   
 | | |)|| |  |)|| |    | |    | ||  `--. 
 /(  (_)|_|  (_)/(     /(     `-'/( __.'[by justaus3r] 
(__)           (__)   (__)      (__)    [ver:{VERSION}]''',
f'''

██╗░░██╗░█████╗░██████╗░██╗███████╗
██║░░██║██╔══██╗██╔══██╗██║██╔════╝
███████║███████║██████╔╝██║█████╗░░
██╔══██║██╔══██║██╔═══╝░██║██╔══╝░░
██║░░██║██║░░██║██║░░░░░██║███████╗
╚═╝░░╚═╝╚═╝░░╚═╝╚═╝░░░░░╚═╝╚══════╝[by justaus3r]
                                    [ver:{VERSION}]''',    
    ]



def HashCreate(string):
    Stringlen = len(string)
    #All MD'S
    hash_object_md2 = MD2.new()
    hash_object_md2.update(string.encode())
    hash_object_md4 = MD4.new()
    hash_object_md4.update(string.encode())
    hash_object_md5 = hashlib.md5(string.encode())
    #All Sha's
    hash_object_sha1 = hashlib.sha1(string.encode())
    hash_object_sha224 = hashlib.sha224(string.encode())
    hash_object_sha256 = hashlib.sha256(string.encode())
    hash_object_sha384 = hashlib.sha384(string.encode())
    hash_object_sha512 = hashlib.sha512(string.encode())
    #blake2b
    hash_object_blake2b = hashlib.blake2b(string.encode())
    #blake2s
    hash_object_blake2s = hashlib.blake2s(string.encode())
    #whirpool
    hash_object_whirlpool = whirlpool.new(string.encode())
    #lm
    hash_object_lm = lmhash.hash(string)
    #nt
    hash_object_nt = nthash.hash(string)
    #ntlm
    hash_object_ntlm_unfiltered = hashlib.new('md4', string.encode('utf-16le')).digest()
    hash_object_filter1 = binascii.hexlify(hash_object_ntlm_unfiltered)
    hash_object_ntlm = hash_object_filter1.decode()
    #rot13
    hash_object_rot13 = codecs.encode(string,'rot13')
    #crc32
    hash_object_crc32_decimal = zlib.crc32(string.encode())
    hash_object_crc32_hex = hex(hash_object_crc32_decimal)
    hash_object_crc32 = hash_object_crc32_hex[2:]
    #Adler32
    hash_object_adler32_decimal = zlib.adler32(string.encode())
    hash_object_adler32_hex = hex(hash_object_adler32_decimal)
    hash_object_adler32 = hash_object_adler32_hex[2:]
    #Base64
    string_bytes = string.encode("ascii")
    base64_bytes = base64.b64encode(string_bytes)
    hash_object_base64 = base64_bytes.decode("ascii")
    #RIPEMD160
    hash_object_ripemd160 = hashlib.new("ripemd160")
    hash_object_ripemd160.update(string.encode())
    #Bcrypt (can change every time due to random salt)
    hash_object_bcrypt_unfiltered = bcrypt.hashpw(string, bcrypt.gensalt())
    hash_object_bcrypt = hash_object_bcrypt_unfiltered
    #argon2
    Hash_obj = PasswordHasher()
    Hash_obj_argon2 = Hash_obj.hash(string)
    #sha256_crypt
    Hash_obj_sha256_crypt = sha256_crypt.hash(string)
    #sha512_crypt
    Hash_obj_sha512_crypt = sha512_crypt.hash(string)
    #pbkdf2_sha256
    Hash_obj_pbkdf2_sha256 = pbkdf2_sha256.hash(string)
    #pbkdf2_sha512
    Hash_obj_pbkdf2_sha512 = pbkdf2_sha512.hash(string)
    #----------------------print_result-------------------
    print("\n[magenta1] ---------------[/magenta1][gold1]--------------------[/gold1]")
    print(f"\n[green]String:[/green] {string}")
    print(f"\n[green]String lenght(Including spaces):[/green] {Stringlen}")
    print("\n[green] ---------------[/green][red]--------------------[/red]")
    print("\n[green] MD2:[/green]",hash_object_md2.hexdigest()+"[red] (Not Secure)[/red]")
    print("\n[green] MD4:[/green]",hash_object_md4.hexdigest()+"[red] (Not Secure)[/red] ")
    print("\n[green] MD5:[/green]",hash_object_md5.hexdigest()+"[red] (Not Secure)[/red] ")
    print("\n[green] Sha1:[/green]",hash_object_sha1.hexdigest()+"[red] (Not Secure)[/red] ")
    print("\n[green] Sha224:[/green]",hash_object_sha224.hexdigest()+"[green] (Secure)[/green]")
    print("\n[green] Sha256:[/green]",hash_object_sha256.hexdigest()+"[green] (Secure)[/green]")
    print("\n[green] Sha384:[/green]",hash_object_sha384.hexdigest()+"[green] (Secure)[/green]")
    print("\n[green] Sha512:[/green]",hash_object_sha512.hexdigest()+"[green] (Secure)[/green]")
    print("\n[green] Blake2b:[/green]",hash_object_blake2b.hexdigest()+"[green] (Secure)[/green]")
    print("\n[green] Blake2s:[/green]",hash_object_blake2s.hexdigest()+"[green] (Secure)[/green]")
    print("\n[green] Whirlpool:[/green]",hash_object_whirlpool.hexdigest()+"[green] (Secure)[/green]")
    print("\n[green] LM:[/green]",hash_object_lm+"[red] (Not Secure)[/red] ")
    print("\n[green] NT:[/green]",hash_object_nt+"[red] (Not Secure)[/red] ")
    print("\n[green] NTLM:[/green]",hash_object_ntlm+"[yellow] (Normal)[/yellow]")
    print("\n[green] rot13:[/green]",hash_object_rot13+"[red] (Not Secure)[/red] ")
    print("\n[green] crc32:[/green]",hash_object_crc32+"[red] (Not Secure)[/red] ")
    print("\n[green] adler32:[/green]",hash_object_adler32+"[yellow] (Normal)[/yellow]")
    print("\n[green] Base64:[/green]",hash_object_base64+"[red] (Not Secure)[/red] ")
    print("\n[green] ripemd_160:[/green]",hash_object_ripemd160.hexdigest()+"[yellow] (Normal)[/yellow]")
    print("\n[green] Bcrypt:[/green]",hash_object_bcrypt+"[green] (Secure)[/green]")
    print("\n[green] Argon2:[/green]",Hash_obj_argon2+"[green] (Secure)[/green]")
    print("\n[green] Sha256_crypt:[/green]",Hash_obj_sha256_crypt+"[green] (Secure)[/green]")
    print("\n[green] Sha512_crypt:[/green]",Hash_obj_sha512_crypt+"[green] (Secure)[/green]")
    print("\n[green] pbkdf2_sha256:[/green]",Hash_obj_pbkdf2_sha256+"[green] (Secure)[/green]")
    print("\n[green] pbkdf2_sha512:[/green]",Hash_obj_pbkdf2_sha512+"[green] (Secure)[/green]")
def HashWrite(string,file):
    #All MD'S
    hash_object_md2 = MD2.new()
    hash_object_md2.update(string.encode())
    hash_object_md4 = MD4.new()
    hash_object_md4.update(string.encode())
    hash_object_md5 = hashlib.md5(string.encode())
    #All Sha's
    hash_object_sha1 = hashlib.sha1(string.encode())
    hash_object_sha224 = hashlib.sha224(string.encode())
    hash_object_sha256 = hashlib.sha256(string.encode())
    hash_object_sha384 = hashlib.sha384(string.encode())
    hash_object_sha512 = hashlib.sha512(string.encode())
    #blake2b
    hash_object_blake2b = hashlib.blake2b(string.encode())
    #blake2s
    hash_object_blake2s = hashlib.blake2s(string.encode())
    #whirpool
    hash_object_whirlpool = whirlpool.new(string.encode())
    #lm
    hash_object_lm = lmhash.hash(string)
    #nt
    hash_object_nt = nthash.hash(string)
    #ntlm
    hash_object_ntlm_unfiltered = hashlib.new('md4', string.encode('utf-16le')).digest()
    hash_object_filter1 = binascii.hexlify(hash_object_ntlm_unfiltered)
    hash_object_ntlm = hash_object_filter1.decode()
    #rot13
    hash_object_rot13 = codecs.encode(string,'rot13')
    #crc32
    hash_object_crc32_decimal = zlib.crc32(string.encode())
    hash_object_crc32_hex = hex(hash_object_crc32_decimal)
    hash_object_crc32 = hash_object_crc32_hex[2:]
    #Adler32
    hash_object_adler32_decimal = zlib.adler32(string.encode())
    hash_object_adler32_hex = hex(hash_object_adler32_decimal)
    hash_object_adler32 = hash_object_adler32_hex[2:]
    #Base64
    string_bytes = string.encode("ascii")
    base64_bytes = base64.b64encode(string_bytes)
    hash_object_base64 = base64_bytes.decode("ascii")
    #RIPEMD160
    hash_object_ripemd160 = hashlib.new("ripemd160")
    hash_object_ripemd160.update(string.encode())
    #Bcrypt (can change every time due to random salt)
    hash_object_bcrypt_unfiltered = bcrypt.hashpw(string, bcrypt.gensalt())
    hash_object_bcrypt = hash_object_bcrypt_unfiltered
    #argon2
    Hash_obj = PasswordHasher()
    Hash_obj_argon2 = Hash_obj.hash(string)
    #sha256_crypt
    Hash_obj_sha256_crypt = sha256_crypt.hash(string)
    #sha512_crypt
    Hash_obj_sha512_crypt = sha512_crypt.hash(string)
    #pbkdf2_sha256
    Hash_obj_pbkdf2_sha256 = pbkdf2_sha256.hash(string)
    #pbkdf2_sha512
    Hash_obj_pbkdf2_sha512 = pbkdf2_sha512.hash(string)
    #Write to file
    File = open(f"{file}","w")
    File.close()
    File = open(f"{file}","a")
    File.write("MD2:"+hash_object_md2.hexdigest()+"\n\n")
    File.write("MD4:"+hash_object_md4.hexdigest()+"\n\n")
    File.write("MD5:"+hash_object_md5.hexdigest()+"\n\n")
    File.write("Sha1:"+hash_object_sha1.hexdigest()+"\n\n")
    File.write("Sha224:"+hash_object_sha224.hexdigest()+"\n\n")
    File.write("Sha256:"+hash_object_sha256.hexdigest()+"\n\n")
    File.write("Sha384:"+hash_object_sha384.hexdigest()+"\n\n")
    File.write("Sha512:"+hash_object_sha512.hexdigest()+"\n\n")
    File.write("Blake2b:"+hash_object_blake2b.hexdigest()+"\n\n")
    File.write("Blake2s:"+hash_object_blake2s.hexdigest()+"\n\n")
    File.write("Whirlpool:"+hash_object_whirlpool.hexdigest()+"\n\n")
    File.write("LM:"+hash_object_lm+"\n\n")
    File.write("NT:"+hash_object_nt+"\n\n")
    File.write("NTLM:"+hash_object_ntlm+"\n\n")
    File.write("rot13:"+hash_object_rot13+"\n\n")
    File.write("crc32:"+hash_object_crc32+"\n\n")
    File.write("adler32:"+hash_object_adler32+"\n\n")
    File.write("Base64:"+hash_object_base64+"\n\n")
    File.write("ripemd_160"+hash_object_ripemd160.hexdigest()+"\n\n")
    File.write("Bcrypt:"+hash_object_bcrypt+"\n\n")
    File.write("Argon2:"+Hash_obj_argon2+"\n\n")
    File.write("sha256_crypt:"+Hash_obj_sha256_crypt+"\n\n")
    File.write("sha512_crypt:"+Hash_obj_sha512_crypt+"\n\n")
    File.write("pbkdf2_sha256:"+Hash_obj_pbkdf2_sha256+"\n\n")
    File.write("pbkdf2_sha512:"+Hash_obj_pbkdf2_sha512+"\n\n")
    File.close()
def HashCreateForFile(string,file):
        hash_object_md2 = MD2.new()
        hash_object_md2.update(string)
        hash_object_md4 = MD4.new()
        hash_object_md4.update(string)
        hash_object_md5 = hashlib.md5(string)
        #All Sha's
        hash_object_sha1 = hashlib.sha1(string)
        hash_object_sha224 = hashlib.sha224(string)
        hash_object_sha256 = hashlib.sha256(string)
        hash_object_sha384 = hashlib.sha384(string)
        hash_object_sha512 = hashlib.sha512(string)
        #blake2b
        hash_object_blake2b = hashlib.blake2b(string)
        #blake2s
        hash_object_blake2s = hashlib.blake2s(string)
        #whirpool
        hash_object_whirlpool = whirlpool.new(string)
        #lm
        hash_object_lm = lmhash.hash(string)
        #nt
        hash_object_nt = nthash.hash(string)
        #crc32
        hash_object_crc32_decimal = zlib.crc32(string)
        hash_object_crc32_hex = hex(hash_object_crc32_decimal)
        hash_object_crc32 = hash_object_crc32_hex[2:]
        #Adler32
        hash_object_adler32_decimal = zlib.adler32(string)
        hash_object_adler32_hex = hex(hash_object_adler32_decimal)
        hash_object_adler32 = hash_object_adler32_hex[2:]
        #Base64
        string_bytes = string
        base64_bytes = base64.b64encode(string_bytes)
        hash_object_base64 = base64_bytes.decode("ascii")
        #RIPEMD160
        hash_object_ripemd160 = hashlib.new("ripemd160")
        hash_object_ripemd160.update(string)
        #Bcrypt (can change every time due to random salt)
        hash_object_bcrypt_unfiltered = bcrypt.hashpw(str(string), bcrypt.gensalt())
        hash_object_bcrypt_filter1 = str(hash_object_bcrypt_unfiltered)
        hash_object_bcrypt_filter2 = hash_object_bcrypt_filter1[1:]
        hash_object_bcrypt = hash_object_bcrypt_filter2.replace("'","")
        #argon2
        Hash_obj = PasswordHasher()
        Hash_obj_argon2 = Hash_obj.hash(string)
        #sha256_crypt
        Hash_obj_sha256_crypt = sha256_crypt.hash(string)
        #sha512_crypt
        Hash_obj_sha512_crypt = sha512_crypt.hash(string)
        #pbkdf2_sha256
        Hash_obj_pbkdf2_sha256 = pbkdf2_sha256.hash(string)
        #pbkdf2_sha512
        Hash_obj_pbkdf2_sha512 = pbkdf2_sha512.hash(string)
        #----------------------print_result-------------------
        print("--------------------------------")
        print(f"\n[green] File:\033[00m{file}")
        print("--------------------------------")
        print("\n[green] MD2:[/green]",hash_object_md2.hexdigest()+"[red] (Not Secure)[/red]")
        print("\n[green] MD4:[/green]",hash_object_md4.hexdigest()+"[red] (Not Secure)[/red]")
        print("\n[green] MD5:[/green]",hash_object_md5.hexdigest()+"[red] (Not Secure)[/red]")
        print("\n[green] Sha1:[/green]",hash_object_sha1.hexdigest()+"[red] (Not Secure)[/red]")
        print("\n[green] Sha224:[/green]",hash_object_sha224.hexdigest()+"[green] (Secure)[/green]")
        print("\n[green] Sha256:[/green]",hash_object_sha256.hexdigest()+"[green] (Secure)[/green]")
        print("\n[green] Sha384:[/green]",hash_object_sha384.hexdigest()+"[green] (Secure)[/green]")
        print("\n[green] Sha512:[/green]",hash_object_sha512.hexdigest()+"[green] (Secure)[/green]")
        print("\n[green] Blake2b:[/green]",hash_object_blake2b.hexdigest()+"[green] (Secure)[/green]")
        print("\n[green] Blake2s:[/green]",hash_object_blake2s.hexdigest()+"[green] (Secure)[/green]")
        print("\n[green] Whirlpool:[/green]",hash_object_whirlpool.hexdigest()+"[green] (Secure)[/green]")
        print("\n[green] LM:[/green]",hash_object_lm+"[red] (Not Secure)[/red]")
        print("\n[green] NT:[/green]",hash_object_nt+"[red] (Not Secure)[/red]")
        print("\n[green] crc32:[/green]",hash_object_crc32+"[red] (Not Secure)[/red]")
        print("\n[green] adler32:[/green]",hash_object_adler32+"[yellow] (Normal)[/yellow]")
        print("\n[green] Base64:[/green]",hash_object_base64+"[red] (Not Secure)[/red]")
        print("\n[green] ripemd_160:[/green]",hash_object_ripemd160.hexdigest()+"[yellow] (Normal)[/yellow]")
        print("\n[green] Bcrypt:[/green]",hash_object_bcrypt+"[green] (Secure)[/green]")
        print("\n[green] Argon2:[/green]",Hash_obj_argon2+"[green] (Secure)[/green]]")
        print("\n[green] Sha256_crypt:[/green]",Hash_obj_sha256_crypt+"[green] (Secure)[/green]")
        print("\n[green] Sha512_crypt:[/green]",Hash_obj_sha512_crypt+"[green] (Secure)[/green]")
        print("\n[green] pbkdf2_sha256:[/green]",Hash_obj_pbkdf2_sha256+"[green] (Secure)[/green]")
        print("\n[green] pbkdf2_sha512:[/green]",Hash_obj_pbkdf2_sha512+"[green] (Secure)[/green]")
def WriteHashForFile(string,outFile,file):
            hash_object_md2 = MD2.new()
            hash_object_md2.update(string)
            hash_object_md4 = MD4.new()
            hash_object_md4.update(string)
            hash_object_md5 = hashlib.md5(string)
            #All Sha's
            hash_object_sha1 = hashlib.sha1(string)
            hash_object_sha224 = hashlib.sha224(string)
            hash_object_sha256 = hashlib.sha256(string)
            hash_object_sha384 = hashlib.sha384(string)
            hash_object_sha512 = hashlib.sha512(string)
            #blake2b
            hash_object_blake2b = hashlib.blake2b(string)
            #blake2s
            hash_object_blake2s = hashlib.blake2s(string)
            #whirpool
            hash_object_whirlpool = whirlpool.new(string)
            #lm
            hash_object_lm = lmhash.hash(string)
            #nt
            hash_object_nt = nthash.hash(string)
            #crc32
            hash_object_crc32_decimal = zlib.crc32(string)
            hash_object_crc32_hex = hex(hash_object_crc32_decimal)
            hash_object_crc32 = hash_object_crc32_hex[2:]
            #Adler32
            hash_object_adler32_decimal = zlib.adler32(string)
            hash_object_adler32_hex = hex(hash_object_adler32_decimal)
            hash_object_adler32 = hash_object_adler32_hex[2:]
            #Base64
            string_bytes = string
            base64_bytes = base64.b64encode(string_bytes)
            hash_object_base64 = base64_bytes.decode("ascii")
            #RIPEMD160
            hash_object_ripemd160 = hashlib.new("ripemd160")
            hash_object_ripemd160.update(string)
            #Bcrypt (can change every time due to random salt)
            hash_object_bcrypt_unfiltered = bcrypt.hashpw(string.decode(), bcrypt.gensalt())
            hash_object_bcrypt_filter1 = str(hash_object_bcrypt_unfiltered)
            hash_object_bcrypt_filter2 = hash_object_bcrypt_filter1[1:]
            hash_object_bcrypt = hash_object_bcrypt_filter2.replace("'","")
            #argon2
            Hash_obj = PasswordHasher()
            Hash_obj_argon2 = Hash_obj.hash(string)
            #sha256_crypt
            Hash_obj_sha256_crypt = sha256_crypt.hash(string)
            #sha512_crypt
            Hash_obj_sha512_crypt = sha512_crypt.hash(string)
            #pbkdf2_sha256
            Hash_obj_pbkdf2_sha256 = pbkdf2_sha256.hash(string)
            #pbkdf2_sha512
            Hash_obj_pbkdf2_sha512 = pbkdf2_sha512.hash(string)
            #----------------------print_result-------------------
            print("--------------------------------")
            print(f"\n[green] File:[/green] {file}")
            print("--------------------------------")
            print("\n[green] MD2:[/green]",hash_object_md2.hexdigest()+"[red] (Not Secure)[/red] ")
            print("\n[green] MD4:[/green]",hash_object_md4.hexdigest()+"[red] (Not Secure)[/red] ")
            print("\n[green] MD5:[/green]",hash_object_md5.hexdigest()+"[red] (Not Secure)[/red] ")
            print("\n[green] Sha1:[/green]",hash_object_sha1.hexdigest()+"[red] (Not Secure)[/red] ")
            print("\n[green] Sha224:[/green]",hash_object_sha224.hexdigest()+"[green] (Secure)[/green]")
            print("\n[green] Sha256:[/green]",hash_object_sha256.hexdigest()+"[green] (Secure)[/green]")
            print("\n[green] Sha384:[/green]",hash_object_sha384.hexdigest()+"[green] (Secure)[/green]")
            print("\n[green] Sha512:[/green]",hash_object_sha512.hexdigest()+"[green] (Secure)[/green]")
            print("\n[green] Blake2b:[/green]",hash_object_blake2b.hexdigest()+"[green] (Secure)[/green]")
            print("\n[green] Blake2s:[/green]",hash_object_blake2s.hexdigest()+"[green] (Secure)[/green]")
            print("\n[green] Whirlpool:[/green]",hash_object_whirlpool.hexdigest()+"[green] (Secure)[/green]")
            print("\n[green] LM:[/green]",hash_object_lm+"[red] (Not Secure)[/red] ")
            print("\n[green] NT:[/green]",hash_object_nt+"[red] (Not Secure)[/red] ")
            print("\n[green] crc32:[/green]",hash_object_crc32+"[red] (Not Secure)[/red] ")
            print("\n[green] adler32:[/green]",hash_object_adler32+"[yellow] (Normal)[/yellow]")
            print("\n[green] Base64:[/green]",hash_object_base64+"[red] (Not Secure)[/red] ")
            print("\n[green] ripemd_160:[/green]",hash_object_ripemd160.hexdigest()+"[yellow] (Normal)[/yellow]")
            print("\n[green] Bcrypt:[/green]",hash_object_bcrypt+"[green] (Secure)[/green]")
            print("\n[green] Argon2:[/green]",Hash_obj_argon2+"[green] (Secure)[/green]")
            print("\n[green] Sha256_crypt:[/green]",Hash_obj_sha256_crypt+"[green] (Secure)[/green]")
            print("\n[green] Sha512_crypt:[/green]",Hash_obj_sha512_crypt+"[green] (Secure)[/green]")
            print("\n[green] pbkdf2_sha256:[/green]",Hash_obj_pbkdf2_sha256+"[green] (Secure)[/green]")
            print("\n[green] pbkdf2_sha512:[/green]",Hash_obj_pbkdf2_sha512+"[green] (Secure)[/green]")
            File = open(f"{outFile}","w")
            File.close()
            File = open(f"{outFile}","a")
            File.write("MD2:"+hash_object_md2.hexdigest()+"\n\n")
            File.write("MD4:"+hash_object_md4.hexdigest()+"\n\n")
            File.write("MD5:"+hash_object_md5.hexdigest()+"\n\n")
            File.write("Sha1:"+hash_object_sha1.hexdigest()+"\n\n")
            File.write("Sha224:"+hash_object_sha224.hexdigest()+"\n\n")
            File.write("Sha256:"+hash_object_sha256.hexdigest()+"\n\n")
            File.write("Sha384:"+hash_object_sha384.hexdigest()+"\n\n")
            File.write("Sha512:"+hash_object_sha512.hexdigest()+"\n\n")
            File.write("Blake2b:"+hash_object_blake2b.hexdigest()+"\n\n")
            File.write("Blake2s:"+hash_object_blake2s.hexdigest()+"\n\n")
            File.write("Whirlpool:"+hash_object_whirlpool.hexdigest()+"\n\n")
            File.write("LM:"+hash_object_lm+"\n\n")
            File.write("NT:"+hash_object_nt+"\n\n")
            File.write("crc32:"+hash_object_crc32+"\n\n")
            File.write("adler32:"+hash_object_adler32+"\n\n")
            File.write("Base64:"+hash_object_base64+"\n\n")
            File.write("ripemd_160"+hash_object_ripemd160.hexdigest()+"\n\n")
            File.write("Bcrypt:"+hash_object_bcrypt+"\n\n")
            File.write("Argon2:"+Hash_obj_argon2+"\n\n")
            File.write("sha256_crypt:"+Hash_obj_sha256_crypt+"\n\n")
            File.write("sha512_crypt:"+Hash_obj_sha512_crypt+"\n\n")
            File.write("pbkdf2_sha256:"+Hash_obj_pbkdf2_sha256+"\n\n")
            File.write("pbkdf2_sha512:"+Hash_obj_pbkdf2_sha512+"\n\n")
            File.close()

def displayBanner():
    banner = random.choice(_banner_list)
    #Colourful banner
    rand_colour_number =random.randint(1,5)
    if rand_colour_number == 1:
        print(f"[red]{banner}[/red]")
    elif rand_colour_number == 2:
        print(f"[green]{banner}[/green]")
    elif rand_colour_number == 3:
        print(f"[cyan]{banner}[/cyan]")
    elif rand_colour_number == 4:
        print(f"[yellow]{banner}[/yellow]")
    else:
        print(f"[purple]{banner}[/purple]")
    print("""
    A tool to play with Hashes.
    Report a bug at x-neron@pm.me
    """
    )

def main():
    if len(sys.argv) == 3 and sys.argv[1] == '-t':
        string = (sys.argv[2])
        for step in progress.track(range(1)):
            step
        HashCreate(string)
    elif len(sys.argv) == 5 and sys.argv[1] == '-t' and sys.argv[3] =='-o':
            string = (sys.argv[2])
            file = (sys.argv[4])
            #using for loop for progress bar
            for step in progress.track(range(1)):
               step
            HashCreate(string)
            HashWrite(string,file)
    elif len(sys.argv) == 3 and sys.argv[1] == '-f':
        file = (sys.argv[2])
        File = open(f"{file}","rb")
        string = File.read()
        for step in progress.track(range(1)):
           step
        HashCreateForFile(string,file)
    elif len(sys.argv) == 5 and sys.argv [1] == '-f' and sys.argv[3] =='-o':
        file = (sys.argv[2])
        File = open(f"{file}","rb")
        outFile = (sys.argv[4])
        string = File.read()
        for step in progress.track(range(1)):
           step
        WriteHashForFile(string,outFile,file)

    else:
        print("[green]Description:[/green]\nA little tool to play with hashes.")
        print("[cyan] (+) Usage:[/cyan]\nHapie.py -t <input string>/-f<input file> [Optional -o <output file>]")
        print("""
           [purple]Example:[/purple]
                  python Hapie.py -t "Hello World"
                  python Hapie.py -f Onichan_no_baka.txt
                 or
                  python Hapie.py -t "Hello World" -o File.txt
                  python Hapie.py -f Onichan_no_baka.txt -o YameteOnichan.txt
                  Report a issue at github.com/justaus3r/Hapie/issues
        """)

displayBanner()
main()
