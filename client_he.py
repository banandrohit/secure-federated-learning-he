# client_he.py
# Client script that can act as:
# - keyholder (generate TenSEAL context with secret key, send public context to server)
# - regular client (fetch public context, encrypt updates with it and send ciphertexts to server)
#
# This demo uses the COVID-19 public API as the sample data source.
#
# WARNING: This is an educational demo. The keyholder holds the secret key locally and must never share it.

import argparse, requests, base64, pickle, time, json, sys
import numpy as np

try:
    import tenseal as ts
except Exception as e:
    print('TenSEAL import failed. Make sure tenseal is installed. Error:', e)
    ts = None

AGG_URL = None  # set from args

def serialize_bytes(b: bytes):
    return base64.b64encode(b).decode('ascii')

def deserialize_bytes(s: str):
    return base64.b64decode(s.encode('ascii'))

def fetch_covid_summary():
    # Public API: https://api.covid19api.com/summary
    import requests
    r = requests.get('https://api.covid19api.com/summary', timeout=10)
    data = r.json().get('Countries', [])
    X = []
    y = []
    for c in data:
        tc = c.get('TotalConfirmed', 0) or 0
        td = c.get('TotalDeaths', 0) or 0
        X.append([tc])
        y.append(td)
    return np.array(X, dtype=float), np.array(y, dtype=float)

def make_update_vector():
    # for demo we compute a simple linear-regression coef on the fetched data (1-D), return as vector
    X, y = fetch_covid_summary()
    if len(X) < 5:
        # fallback synthetic
        X = np.arange(10).reshape(-1,1).astype(float)
        y = (X.flatten() * 0.5 + 2.0) + np.random.randn(len(X))*0.1
    # linear closed-form: coef = (X^T X)^{-1} X^T y  (1-D)
    XtX = X.T.dot(X)
    coef = np.linalg.pinv(XtX).dot(X.T).dot(y)
    return coef.flatten()  # 1-D vector

def create_and_send_public_context(poly_mod_degree=8192):
    global AGG_URL
    if ts is None:
        print('TenSEAL not available. Cannot create context.')
        return
    context = ts.context(ts.SCHEME_TYPE.CKKS, poly_mod_degree, -1, [60,40,40,60])
    context.global_scale = 2**40
    context.generate_galois_keys()
    context.generate_relin_keys()
    # serialize WITHOUT secret key so aggregator doesn't get secret
    ctx_bytes = context.serialize(save_secret_key=False)
    payload = {'context': serialize_bytes(ctx_bytes)}
    resp = requests.post(AGG_URL + '/init_public_context', json=payload)
    print('init_public_context response:', resp.json())
    # Save secret context locally for decryption later (this is the keyholder)
    with open('local_secret_context.ctx', 'wb') as f:
        f.write(context.serialize())
    print('Saved local secret context to local_secret_context.ctx (keep it secret!)')

def fetch_public_context():
    global AGG_URL
    resp = requests.get(AGG_URL + '/get_public_context')
    if resp.status_code != 200:
        print('No public context on server yet. Status:', resp.status_code, resp.text)
        return None
    import base64
    ctx_b64 = resp.json()['context']
    return base64.b64decode(ctx_b64.encode('ascii'))

def encrypt_and_send_update(public_ctx_bytes):
    global AGG_URL
    if ts is None:
        print('TenSEAL not available. Falling back to masked (simulated) mode.')
        # Simulated: send plain vector (insecure) - demo fallback
        v = make_update_vector()
        import base64, pickle
        payload = {'ciphertext': base64.b64encode(pickle.dumps(v)).decode('ascii')}
        requests.post(AGG_URL + '/upload_enc', json=payload)
        print('Sent plaintext fallback as bytes (insecure).')
        return
    # create context from public bytes (this context has no secret key)
    public_ctx = ts.context_from(public_ctx_bytes)
    # build ckks_vector and encrypt update
    v = make_update_vector()
    ck = ts.ckks_vector(public_ctx, v.tolist())
    raw = ck.serialize()
    import base64
    payload = {'ciphertext': base64.b64encode(raw).decode('ascii')}
    resp = requests.post(AGG_URL + '/upload_enc', json=payload)
    print('upload_enc response:', resp.json())

def get_all_ciphertexts_and_decrypt():
    # The keyholder loads its local secret context and fetches all ciphertexts from aggregator,
    # deserializes them with the secret context, does homomorphic addition and averaging, decrypts result,
    # and posts the plaintext back to server.
    global AGG_URL
    # load local secret context bytes
    try:
        with open('local_secret_context.ctx','rb') as f:
            secret_ctx_bytes = f.read()
    except Exception as e:
        print('Cannot load local secret context (local_secret_context.ctx). Error:', e)
        return
    if ts is None:
        print('TenSEAL not available; cannot decrypt.')
        return
    secret_ctx = ts.context_from(secret_ctx_bytes)
    # fetch ciphertexts
    resp = requests.get(AGG_URL + '/get_agg_cipher')
    if resp.status_code != 200:
        print('No ciphertexts ready or error:', resp.status_code, resp.text)
        return
    ciphers_b64 = resp.json().get('ciphertexts', [])
    if not ciphers_b64:
        print('No ciphertexts returned.')
        return
    # deserialize each under secret_ctx, sum them, average, decrypt
    vecs = []
    for s in ciphers_b64:
        raw = base64.b64decode(s.encode('ascii'))
        try:
            ck = ts.ckks_vector_from(secret_ctx, raw)
        except Exception as e:
            print('Failed to deserialize ciphertext with secret context:', e)
            return
        vecs.append(ck)
    # perform homomorphic sum on vectors (start with first)
    agg = vecs[0]
    for c in vecs[1:]:
        agg = agg + c
    # average
    scale = 1.0 / len(vecs)
    agg = agg * scale
    # decrypt
    plain = agg.decrypt()
    # post plaintext back to server
    import base64, json
    payload = {'plaintext_aggregate': json.dumps([float(x) for x in plain])}
    resp2 = requests.post(AGG_URL + '/post_decrypted', json=payload)
    print('Posted decrypted aggregate, server response:', resp2.json())

if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--agg', required=True, help='Aggregator base URL, e.g. http://192.168.1.10:5000')
    parser.add_argument('--role', default='client', choices=['client','keyholder','decryptor'], help='role: client (encrypt+upload), keyholder (init context), decryptor (fetch and decrypt)')
    args = parser.parse_args()
    AGG_URL = args.agg.rstrip('/')

    if args.role == 'keyholder':
        print('Running keyholder: creating TenSEAL context and posting public context to aggregator...')
        create_and_send_public_context()
        sys.exit(0)

    public_ctx = fetch_public_context()
    if public_ctx is None:
        print('No public context available. If you are the first user, run with --role keyholder to create it.')
        sys.exit(0)

    if args.role == 'client':
        print('Encrypting local update and sending to aggregator...')
        encrypt_and_send_update(public_ctx)
    elif args.role == 'decryptor':
        print('Fetching ciphertexts and performing decryption locally (requires local secret context file).') 
        get_all_ciphertexts_and_decrypt()
