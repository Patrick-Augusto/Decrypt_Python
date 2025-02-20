import os
import argparse
from Crypto.Cipher import AES
from Crypto.Util.Padding import unpad
from Crypto.Util import Counter

def decrypt_cbc(data, key):
    """
    Tenta descriptografar usando AES em modo CBC.
    Supõe que os 16 primeiros bytes sejam o IV e que o padding PKCS7 foi utilizado.
    """
    try:
        iv = data[:16]
        cipher_text = data[16:]
        cipher = AES.new(key, AES.MODE_CBC, iv)
        decrypted = unpad(cipher.decrypt(cipher_text), AES.block_size)
        return decrypted
    except Exception as e:
        print("Falha na descriptografia CBC:", e)
        return None

def decrypt_gcm(data, key):
    """
    Tenta descriptografar usando AES em modo GCM.
    Supõe que os 12 primeiros bytes sejam o nonce e os 16 últimos bytes a tag.
    """
    try:
        if len(data) < 12 + 16:
            print("Dados insuficientes para GCM.")
            return None
        nonce = data[:12]
        tag = data[-16:]
        cipher_text = data[12:-16]
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        decrypted = cipher.decrypt_and_verify(cipher_text, tag)
        return decrypted
    except Exception as e:
        print("Falha na descriptografia GCM:", e)
        return None

def decrypt_ctr(data, key):
    """
    Tenta descriptografar usando AES em modo CTR.
    Supõe que os 8 primeiros bytes sejam o nonce; esse valor pode variar conforme a implementação.
    """
    try:
        nonce = data[:8]
        cipher_text = data[8:]
        ctr = Counter.new(64, prefix=nonce, initial_value=0)
        cipher = AES.new(key, AES.MODE_CTR, counter=ctr)
        decrypted = cipher.decrypt(cipher_text)
        return decrypted
    except Exception as e:
        print("Falha na descriptografia CTR:", e)
        return None

def attempt_decrypt_file(file_path, key):
    print(f"Processando o arquivo: {file_path}")
    try:
        with open(file_path, "rb") as f:
            data = f.read()
    except Exception as e:
        print("Erro ao ler o arquivo:", e)
        return

    # Tenta descriptografar com CBC
    print("Tentando descriptografia CBC...")
    result = decrypt_cbc(data, key)
    if result:
        new_file = file_path + "_cbc_decrypted"
        with open(new_file, "wb") as out:
            out.write(result)
        print(f"Descriptografia CBC bem-sucedida: {new_file}")
        return

    # Tenta descriptografar com GCM
    print("Tentando descriptografia GCM...")
    result = decrypt_gcm(data, key)
    if result:
        new_file = file_path + "_gcm_decrypted"
        with open(new_file, "wb") as out:
            out.write(result)
        print(f"Descriptografia GCM bem-sucedida: {new_file}")
        return

    # Tenta descriptografar com CTR
    print("Tentando descriptografia CTR...")
    result = decrypt_ctr(data, key)
    if result:
        new_file = file_path + "_ctr_decrypted"
        with open(new_file, "wb") as out:
            out.write(result)
        print(f"Descriptografia CTR bem-sucedida: {new_file}")
        return

    print("Não foi possível descriptografar o arquivo:", file_path)

def process_folder(folder, key):
    for root, dirs, files in os.walk(folder):
        for file in files:
            file_path = os.path.join(root, file)
            attempt_decrypt_file(file_path, key)

def main():
    parser = argparse.ArgumentParser(description="Decoder universal AES para descriptografar arquivos de uma pasta")
    parser.add_argument("folder", help="Caminho da pasta com arquivos criptografados")
    parser.add_argument("key", help="Chave de descriptografia em hexadecimal")
    args = parser.parse_args()
    
    try:
        key = bytes.fromhex(args.key)
    except Exception as e:
        print("Formato de chave inválido (deve ser hexadecimal):", e)
        return

    process_folder(args.folder, key)

if __name__ == "__main__":
    main()