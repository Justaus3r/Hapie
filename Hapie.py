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
from rich.progress import track
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
    hash_object_filter2 = str(hash_object_filter1)
    hash_object_filter3 = hash_object_filter2[1:]
    hash_object_ntlm = hash_object_filter3.replace("'","")
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
    hash_object_bcrypt_unfiltered = bcrypt.hashpw(string.encode(), bcrypt.gensalt())
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
    #used Ascii escape character's to print coloured text for ex: \033[96m {}\033[00m
    print("\n\033[96m ---------------\033[00m\033[91m--------------------\033[00m")
    print(f"\n\033[96m String:\033[00m{string}")
    print(f"\n\033[96m String lenght(Including spaces):\033[00m{Stringlen}")
    print("\n\033[96m ---------------\033[00m\033[91m--------------------\033[00m")
    print("\n\033[96m MD2:\033[00m",hash_object_md2.hexdigest()+"\033[91m (Not Secure)\033[00m ")
    print("\n\033[96m MD4:\033[00m",hash_object_md4.hexdigest()+"\033[91m (Not Secure)\033[00m ")
    print("\n\033[96m MD5:\033[00m",hash_object_md5.hexdigest()+"\033[91m (Not Secure)\033[00m ")
    print("\n\033[96m Sha1:\033[00m",hash_object_sha1.hexdigest()+"\033[91m (Not Secure)\033[00m ")
    print("\n\033[96m Sha224:\033[00m",hash_object_sha224.hexdigest()+"\033[92m (Secure)\033[00m")
    print("\n\033[96m Sha256:\033[00m",hash_object_sha256.hexdigest()+"\033[92m (Secure)\033[00m")
    print("\n\033[96m Sha384:\033[00m",hash_object_sha384.hexdigest()+"\033[92m (Secure)\033[00m")
    print("\n\033[96m Sha512:\033[00m",hash_object_sha512.hexdigest()+"\033[92m (Secure)\033[00m")
    print("\n\033[96m Blake2b:\033[00m",hash_object_blake2b.hexdigest()+"\033[92m (Secure)\033[00m")
    print("\n\033[96m Blake2s:\033[00m",hash_object_blake2s.hexdigest()+"\033[92m (Secure)\033[00m")
    print("\n\033[96m Whirlpool:\033[00m",hash_object_whirlpool.hexdigest()+"\033[92m (Secure)\033[00m")
    print("\n\033[96m LM:\033[00m",hash_object_lm+"\033[91m (Not Secure)\033[00m ")
    print("\n\033[96m NT:\033[00m",hash_object_nt+"\033[91m (Not Secure)\033[00m ")
    print("\n\033[96m NTLM:\033[00m",hash_object_ntlm+"\033[93m (Normal)\033[00m")
    print("\n\033[96m rot13:\033[00m",hash_object_rot13+"\033[91m (Not Secure)\033[00m ")
    print("\n\033[96m crc32:\033[00m",hash_object_crc32+"\033[91m (Not Secure)\033[00m ")
    print("\n\033[96m adler32:\033[00m",hash_object_adler32+"\033[93m (Normal)\033[00m")
    print("\n\033[96m Base64:\033[00m",hash_object_base64+"\033[91m (Not Secure)\033[00m ")
    print("\n\033[96m ripemd_160:\033[00m",hash_object_ripemd160.hexdigest()+"\033[93m (Normal)\033[00m")
    print("\n\033[96m Bcrypt:\033[00m",hash_object_bcrypt+"\033[92m (Secure)\033[00m")
    print("\n\033[96m Argon2:\033[00m",Hash_obj_argon2+"\033[92m (Secure)\033[00m")
    print("\n\033[96m Sha256_crypt:\033[00m",Hash_obj_sha256_crypt+"\033[92m (Secure)\033[00m")
    print("\n\033[96m Sha512_crypt:\033[00m",Hash_obj_sha512_crypt+"\033[92m (Secure)\033[00m")
    print("\n\033[96m pbkdf2_sha256:\033[00m",Hash_obj_pbkdf2_sha256+"\033[92m (Secure)\033[00m")
    print("\n\033[96m pbkdf2_sha512:\033[00m",Hash_obj_pbkdf2_sha512+"\033[92m (Secure)\033[00m")
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
    hash_object_filter2 = str(hash_object_filter1)
    hash_object_filter3 = hash_object_filter2[1:]
    hash_object_ntlm = hash_object_filter3.replace("'","")
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
    hash_object_bcrypt_unfiltered = bcrypt.hashpw(string.encode(), bcrypt.gensalt())
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
        hash_object_bcrypt_unfiltered = bcrypt.hashpw(string, bcrypt.gensalt())
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
        #used Ascii escape character's to print coloured text for ex: \033[96m {}\033[00m
        print("--------------------------------")
        print(f"\n\033[96m File:\033[00m{file}")
        print("--------------------------------")
        print("\n\033[96m MD2:\033[00m",hash_object_md2.hexdigest()+"\033[91m (Not Secure)\033[00m ")
        print("\n\033[96m MD4:\033[00m",hash_object_md4.hexdigest()+"\033[91m (Not Secure)\033[00m ")
        print("\n\033[96m MD5:\033[00m",hash_object_md5.hexdigest()+"\033[91m (Not Secure)\033[00m ")
        print("\n\033[96m Sha1:\033[00m",hash_object_sha1.hexdigest()+"\033[91m (Not Secure)\033[00m ")
        print("\n\033[96m Sha224:\033[00m",hash_object_sha224.hexdigest()+"\033[92m (Secure)\033[00m")
        print("\n\033[96m Sha256:\033[00m",hash_object_sha256.hexdigest()+"\033[92m (Secure)\033[00m")
        print("\n\033[96m Sha384:\033[00m",hash_object_sha384.hexdigest()+"\033[92m (Secure)\033[00m")
        print("\n\033[96m Sha512:\033[00m",hash_object_sha512.hexdigest()+"\033[92m (Secure)\033[00m")
        print("\n\033[96m Blake2b:\033[00m",hash_object_blake2b.hexdigest()+"\033[92m (Secure)\033[00m")
        print("\n\033[96m Blake2s:\033[00m",hash_object_blake2s.hexdigest()+"\033[92m (Secure)\033[00m")
        print("\n\033[96m Whirlpool:\033[00m",hash_object_whirlpool.hexdigest()+"\033[92m (Secure)\033[00m")
        print("\n\033[96m LM:\033[00m",hash_object_lm+"\033[91m (Not Secure)\033[00m ")
        print("\n\033[96m NT:\033[00m",hash_object_nt+"\033[91m (Not Secure)\033[00m ")
        print("\n\033[96m crc32:\033[00m",hash_object_crc32+"\033[91m (Not Secure)\033[00m ")
        print("\n\033[96m adler32:\033[00m",hash_object_adler32+"\033[93m (Normal)\033[00m")
        print("\n\033[96m Base64:\033[00m",hash_object_base64+"\033[91m (Not Secure)\033[00m ")
        print("\n\033[96m ripemd_160:\033[00m",hash_object_ripemd160.hexdigest()+"\033[93m (Normal)\033[00m")
        print("\n\033[96m Bcrypt:\033[00m",hash_object_bcrypt+"\033[92m (Secure)\033[00m")
        print("\n\033[96m Argon2:\033[00m",Hash_obj_argon2+"\033[92m (Secure)\033[00m")
        print("\n\033[96m Sha256_crypt:\033[00m",Hash_obj_sha256_crypt+"\033[92m (Secure)\033[00m")
        print("\n\033[96m Sha512_crypt:\033[00m",Hash_obj_sha512_crypt+"\033[92m (Secure)\033[00m")
        print("\n\033[96m pbkdf2_sha256:\033[00m",Hash_obj_pbkdf2_sha256+"\033[92m (Secure)\033[00m")
        print("\n\033[96m pbkdf2_sha512:\033[00m",Hash_obj_pbkdf2_sha512+"\033[92m (Secure)\033[00m")
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
            hash_object_bcrypt_unfiltered = bcrypt.hashpw(string, bcrypt.gensalt())
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
            #used Ascii escape character's to print coloured text for ex: \033[96m {}\033[00m
            print("--------------------------------")
            print(f"\n\033[96m File:\033[00m{file}")
            print("--------------------------------")
            print("\n\033[96m MD2:\033[00m",hash_object_md2.hexdigest()+"\033[91m (Not Secure)\033[00m ")
            print("\n\033[96m MD4:\033[00m",hash_object_md4.hexdigest()+"\033[91m (Not Secure)\033[00m ")
            print("\n\033[96m MD5:\033[00m",hash_object_md5.hexdigest()+"\033[91m (Not Secure)\033[00m ")
            print("\n\033[96m Sha1:\033[00m",hash_object_sha1.hexdigest()+"\033[91m (Not Secure)\033[00m ")
            print("\n\033[96m Sha224:\033[00m",hash_object_sha224.hexdigest()+"\033[92m (Secure)\033[00m")
            print("\n\033[96m Sha256:\033[00m",hash_object_sha256.hexdigest()+"\033[92m (Secure)\033[00m")
            print("\n\033[96m Sha384:\033[00m",hash_object_sha384.hexdigest()+"\033[92m (Secure)\033[00m")
            print("\n\033[96m Sha512:\033[00m",hash_object_sha512.hexdigest()+"\033[92m (Secure)\033[00m")
            print("\n\033[96m Blake2b:\033[00m",hash_object_blake2b.hexdigest()+"\033[92m (Secure)\033[00m")
            print("\n\033[96m Blake2s:\033[00m",hash_object_blake2s.hexdigest()+"\033[92m (Secure)\033[00m")
            print("\n\033[96m Whirlpool:\033[00m",hash_object_whirlpool.hexdigest()+"\033[92m (Secure)\033[00m")
            print("\n\033[96m LM:\033[00m",hash_object_lm+"\033[91m (Not Secure)\033[00m ")
            print("\n\033[96m NT:\033[00m",hash_object_nt+"\033[91m (Not Secure)\033[00m ")
            print("\n\033[96m crc32:\033[00m",hash_object_crc32+"\033[91m (Not Secure)\033[00m ")
            print("\n\033[96m adler32:\033[00m",hash_object_adler32+"\033[93m (Normal)\033[00m")
            print("\n\033[96m Base64:\033[00m",hash_object_base64+"\033[91m (Not Secure)\033[00m ")
            print("\n\033[96m ripemd_160:\033[00m",hash_object_ripemd160.hexdigest()+"\033[93m (Normal)\033[00m")
            print("\n\033[96m Bcrypt:\033[00m",hash_object_bcrypt+"\033[92m (Secure)\033[00m")
            print("\n\033[96m Argon2:\033[00m",Hash_obj_argon2+"\033[92m (Secure)\033[00m")
            print("\n\033[96m Sha256_crypt:\033[00m",Hash_obj_sha256_crypt+"\033[92m (Secure)\033[00m")
            print("\n\033[96m Sha512_crypt:\033[00m",Hash_obj_sha512_crypt+"\033[92m (Secure)\033[00m")
            print("\n\033[96m pbkdf2_sha256:\033[00m",Hash_obj_pbkdf2_sha256+"\033[92m (Secure)\033[00m")
            print("\n\033[96m pbkdf2_sha512:\033[00m",Hash_obj_pbkdf2_sha512+"\033[92m (Secure)\033[00m")
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

#For coloured text
from colorama import Fore, Back, Style
rand_num = random.randint(1,10)
file = open("banner/" + f'banner{rand_num}.txt',"r")
if file.mode == "r":
    banner = file.read()
    #Colourful banner
    rand_colour_number =random.randint(1,5)
    if rand_colour_number == 1:
        print(Fore.RED+banner)
    elif rand_colour_number == 2:
        print(Fore.GREEN+banner)
    elif rand_colour_number == 3:
        print(Fore.BLUE+banner)
    elif rand_colour_number == 4:
        print(Fore.YELLOW+banner)
    else:
        print(Fore.MAGENTA+banner)
print("""
A tool to play with Hashes.
Report a bug at x-neron@pm.me
"""
)
print(Style.RESET_ALL)
if len(sys.argv) == 3 and sys.argv[1] == '-t':
    string = (sys.argv[2])
    for step in track(range(1)):
        step
    HashCreate(string)
elif len(sys.argv) == 5 and sys.argv[1] == '-t' and sys.argv[3] =='-o':
    #MAybeNot.....! yeah i know am lazy to define functions so i copied the code above for this argument too..
        string = (sys.argv[2])
        file = (sys.argv[4])
        #using for loop for progress bar
        for step in track(range(1)):
           step
        HashCreate(string)
        HashWrite(string,file)
elif len(sys.argv) == 3 and sys.argv[1] == '-f':
    file = (sys.argv[2])
    File = open(f"{file}","rb")
    string = File.read()
    for step in track(range(1)):
       step
    HashCreateForFile(string,file)
elif len(sys.argv) == 5 and sys.argv [1] == '-f' and sys.argv[3] =='-o':
    file = (sys.argv[2])
    File = open(f"{file}","rb")
    outFile = (sys.argv[4])
    string = File.read()
    for step in track(range(1)):
       step
    WriteHashForFile(string,outFile,file)

else:
    print("\033[95m Description:\033[00m\nA little tool to play with hashes.")
    print("\033[94m (+) Usage:\033[00m\nHapie.py -t <input string>/-f<input file> [Optional -o <output file>]")
    print("""
       \033[92m Example:\033[00m
              python Hapie.py -t "Hello World"
              python Hapie.py -f Onichan_no_baka.txt
             or
              python Hapie.py -t "Hello World" -o File.txt
              python Hapie.py -f Onichan_no_baka.txt -o YameteOnichan.txt
              Report a issue at github.com/justaus3r/Hapie/issues
    """)
