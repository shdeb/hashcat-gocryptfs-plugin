#!/usr/bin/env python3
import struct
import sys
import json
import base64
import os
from hashlib import scrypt
import time
# import chardet
# from cryptography.hazmat.primitives.ciphers.aead import AESGCM
# from cryptography.hazmat.primitives import hashes
# from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from Crypto.Protocol.KDF import HKDF, scrypt
from Crypto.Hash import SHA256
from Crypto.Cipher import AES
import hcsp
import hcshared

# ====================== GLOBALS ======================


def hkdf_derive(key: bytes, info: bytes, length: int = 32) -> bytes:
    # hkdf = HKDF(
    #     algorithm=hashes.SHA256(),
    #     length=length,
    #     salt=None,
    #     info=info,
    # )
    return HKDF(
        master=key,
        key_len=length,
        salt=None,           # None = no salt
        hashmod=SHA256,
        context=info         # 'context' in pycryptodome = 'info' in cryptography
    )

# input Hash format hash*salt e.g gocryptfs*Z:path/to/your/gocryptfs.conf
def calc_hash(password: bytes, salt_dict: dict) -> str:
    try:
        # isprint = seconds and not (seconds % 2)
        # print("\npassword :",password)

        esalt = salt_dict['esalt']
        salt = esalt['salt_buf']
        N = esalt['scrypt_N']
        R = esalt['scrypt_r']
        P = esalt['scrypt_p']

        # salt = hcshared.get_salt_buf(salt_dict)
        # N = hcshared.get_scrypt_N(salt_dict)
        # R = hcshared.get_scrypt_r(salt_dict)
        # P = hcshared.get_scrypt_p(salt_dict)

        scrypt_key = scrypt(password, salt=salt, N=N, r=R, p=P, key_len=32) #, maxmem=256 * 1024 * 1024)
        # print("scrypt hash :",scrypt_key.hex())
        # term({})

        gcm_key = hkdf_derive(scrypt_key, b"AES-GCM file content encryption", 32)
        # print("gcm_key :",gcm_key.hex())

        nonce = esalt['nonce']
        ciphertext = esalt['ciphertext']
        tag = esalt['tag']

        # iv_len = 16
        # # encrypted_key = hcshared.get_item(salt_dict,'encrypted_key')
        # encrypted_key = bytes(salt_dict['esalt']['encrypted_key'])
        # nonce = encrypted_key[:iv_len]
        # ciphertext = encrypted_key[iv_len:-16]      # everything except the last 16 bytes (tag)
        # tag = encrypted_key[-16:]                   # last 16 bytes = authentication tag

        # print("nonce :",nonce.hex())
        # print("ciphertext + tag :",ciphertext.hex(),tag.hex())

        a_data = (0).to_bytes(8, 'big')
        # print(a_data.hex())

        # Decrypt
        cipher = AES.new(gcm_key, AES.MODE_GCM, nonce=nonce)
        cipher.update(a_data)                       # Add AAD before decrypt
        masterkey = cipher.decrypt_and_verify(ciphertext, tag)

        bmk = masterkey.hex()

        # # Success
        pw_str = password.decode('utf-8', errors='replace')
        print(f"\n✅ PASSWORD FOUND: {pw_str}")
        print(f"Masterkey: {bmk}")

        # return the format's hash part (but hashcat still doesn't say cracked status ¯\_(ツ)_/¯, 
        # so lookout for above output in teminal)
        return "gocryptfs"

    except Exception as e:
        # print(e)
        # input()
        return "0" * 16

# input Hash format HASH*SALT e.g gocryptfs*Z:path/to/your/gocryptfs.conf
def extract_esalts(esalts_buf):
  esalts=[]
  for hash_buf, hash_len, salt_buf, salt_len in struct.iter_unpack("1024s I 1024s I", esalts_buf):
    hash_buf = hash_buf[0:hash_len]
    salt_buf = salt_buf[0:salt_len]
    # print("\nRaw hash_buf :", repr(hash_buf))
    # print("Raw salt_buf :", repr(salt_buf))
    
    config_path,salt,encrypted_key,nonce,ciphertext,tag,N,P,R = '.\\Python\\gocryptfs.conf',None,None,None,None,None,None,None,None
    # === Try different decodings ===
    for encoding in ['utf-8', 'utf-16-le', 'utf-16', 'latin1', 'cp1252']:
        try:
            config_path = salt_buf.decode(encoding).strip('\x00')
            # print(f"Decoded with {encoding}: {config_path}")
            break
        except:
            continue

    if not config_path:
        config_path = salt_buf.decode('utf-8', errors='replace')
        # print("Fallback decode:", config_path)
    # config_path = salt_buf.decode('utf-8').strip('\x00')

    if not os.path.isfile(config_path):
        pass # print(f"gocryptfs.conf not found: {config_path}")
    else:
        with open(config_path, 'r') as f:
            conf = json.load(f)

        sc = conf['ScryptObject']
        if sc:
            salt = base64.b64decode(sc['Salt'])
            encrypted_key = base64.b64decode(conf['EncryptedKey'])
            iv_len = 16
            nonce = encrypted_key[:iv_len]
            ciphertext = encrypted_key[iv_len:-16]      # everything except the last 16 bytes (tag)
            tag = encrypted_key[-16:]                   # last 16 bytes = authentication tag

            N = sc['N']
            R = sc['R']
            P = sc['P']
        
    esalts.append({ "hash_buf"      : hash_buf, 
                    "salt_buf"      : salt,
                    "scrypt_N"      : N,     
                    "scrypt_r"      : R,     
                    "scrypt_p"      : P,
                    # "encrypted_key" : encrypted_key,
                    "nonce"         : nonce,
                    "ciphertext"    : ciphertext,
                    "tag"           : tag,
                    "config_path"   : salt_buf
                    })

  return esalts

def init(ctx):

    # hcshared.dump_hashcat_ctx(ctx) #enable this to dump the ctx from hashcat
    
    hcsp.init(ctx,extract_esalts)
    # print("\nafter extract salt_buf : ",ctx['salts'][0]['esalt']['salt_buf'].hex())
    # hcshared.dump_hashcat_ctx(ctx)
    

    print(f"\n[+] gocryptfs HKDF plugin loaded")
    # print(f"    Config: {ctx['salts'][0]['esalt']['config_path']}")
    # print(f"    Scrypt N={ctx['salts'][0]['esalt']['scrypt_N']} | EncryptedKey={len(ctx['salts'][0]['esalt']['encrypted_key'])} bytes")

    

def term(ctx):
    hcsp.term(ctx)


def kernel_loop(ctx, passwords, salt_id, is_selftest):
    return hcsp.handle_queue(ctx, passwords, salt_id, is_selftest)
