import numpy as np
import time
from hevec_py import (
    Client, Message, SecretKey, SwitchingKey, AutedModPackKeys,
    AutedModPackMLWEKeys, MLWECiphertext, Server, CachedQuery, CachedKeys, Ciphertext
)

# Constants
LOG_RANK = 7
RANK = 2 ** LOG_RANK
DEGREE = 4096
N = DEGREE
LOG_SCALE = 26.25

def main():
    client = Client(LOG_RANK)

    # Generate HE keys
    sec_key = SecretKey()
    relin_key = SwitchingKey()
    auted_mod_pack_keys = AutedModPackKeys(RANK)
    auted_mod_pack_mlwe_keys = AutedModPackMLWEKeys(RANK)

    client.gen_sec_key(sec_key)
    client.gen_relin_key(relin_key, sec_key)
    client.gen_auted_mod_pack_keys(auted_mod_pack_keys, sec_key)
    client.gen_inv_auted_mod_pack_keys(auted_mod_pack_mlwe_keys, sec_key)

    # Generate a random query vector
    query_msg = Message(RANK)
    query_data = np.random.randint(-128, 128, size=RANK, dtype=np.int8) / 128.0
    query_norm = np.sqrt(np.sum(query_data * query_data))
    query_data /= query_norm

    for i in range(RANK):
        query_msg[i] = query_data[i]

    # Generate random key vectors
    key_msgs = []
    for i in range(DEGREE):
        key_msg = Message(RANK)
        key_data = np.random.randint(-128, 128, size=RANK, dtype=np.int8) / 128.0
        key_norm = np.sqrt(np.sum(key_data * key_data))
        key_data /= key_norm
        
        for j in range(RANK):
            key_msg[j] = key_data[j]
        key_msgs.append(key_msg)

    scale = 2.0 ** LOG_SCALE

    # Encrypt the query and keys
    query = MLWECiphertext(RANK)
    mlwe_keys = []

    client.encrypt_query(query, query_msg, sec_key, scale)

    for i in range(N):
        key = MLWECiphertext(RANK)
        client.encrypt_key(key, key_msgs[i], sec_key, scale)
        mlwe_keys.append(key)

    # The server computes the inner product.
    server = Server(LOG_RANK, relin_key, auted_mod_pack_keys, auted_mod_pack_mlwe_keys)
    
    # Cache the query and keys for efficiency
    query_cache = CachedQuery(RANK)
    server.cache_query(query_cache, query)
    
    key_cache = CachedKeys(RANK)
    server.cache_keys(key_cache, mlwe_keys)

    # Compute inner product
    res = Ciphertext()
    server.inner_product(res, query_cache, key_cache)

    # Decrypt the result
    double_scale = 2.0 ** (2 * LOG_SCALE)
    dmsg = Message(DEGREE)
    client.decrypt(dmsg, res, sec_key, double_scale)

    # Compute the expected result for verification
    answer = np.zeros(DEGREE)
    for i in range(N):
        for j in range(RANK):
            answer[i] += query_data[j] * key_msgs[i][j]

    # Calculate the maximum error
    max_error = 0.0
    for i in range(N):
        error = abs(answer[i] - dmsg[i])
        max_error = max(max_error, error)

    print(f"Max error: {max_error}")

if __name__ == "__main__":
    main() 
