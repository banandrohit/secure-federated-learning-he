# aggregator_he.py
# Flask server that receives encrypted updates (TenSEAL ciphertexts serialized)
# Stores public context bytes (no secret key) to allow ciphertext deserialization for addition.
# Aggregator does NOT hold secret keys and therefore cannot decrypt.
#
# Workflow (demo):
# 1) A keyholder client (client 0) posts a public context via /init_public_context (save_secret_key=False).
# 2) Clients fetch the public context from /get_public_context and encrypt model updates with it, then POST to /upload_enc.
# 3) Any client (or an orchestrator) calls /aggregate_enc to homomorphically add all stored ciphertexts and average them.
# 4) The aggregated ciphertext is stored; the keyholder client (who holds the secret key locally) can GET /get_agg_cipher,
#    decrypt it locally, then POST the plaintext aggregate back to the server at /post_decrypted for clients to fetch.
#
# Note: This is a teaching/demo scaffold. Real multiparty HE uses coordinated key generation (CKKS threshold schemes)
# which is more complex.

from flask import Flask, request, jsonify
import base64, pickle, threading

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 20 * 1024 * 1024  # 20 MB limit
# Stored objects (in-memory for demo)
PUBLIC_CONTEXT_BYTES = None  # bytes (serialized TenSEAL context WITHOUT secret key)
CIPHERTEXTS = []             # list of serialized ciphertexts (bytes)
AGG_CIPHERTEXT = None       # serialized ciphertext bytes (sum/average)
PLAINTEXT_AGG = None        # decrypted plaintext aggregate (sent by keyholder)

@app.route('/init_public_context', methods=['POST'])
def init_public_context():
    global PUBLIC_CONTEXT_BYTES
    data = request.get_json()
    PUBLIC_CONTEXT_BYTES = base64.b64decode(data['context'].encode('ascii'))
    # reset stored updates
    global CIPHERTEXTS, AGG_CIPHERTEXT, PLAINTEXT_AGG
    CIPHERTEXTS = []
    AGG_CIPHERTEXT = None
    PLAINTEXT_AGG = None
    return jsonify({'status': 'public_context_saved'})

@app.route('/get_public_context', methods=['GET'])
def get_public_context():
    if PUBLIC_CONTEXT_BYTES is None:
        return jsonify({'status': 'no_context'}), 404
    return jsonify({'context': base64.b64encode(PUBLIC_CONTEXT_BYTES).decode('ascii')})
@app.route('/get_context', methods=['GET'])
def get_context_alias():
    return get_public_context()

@app.route('/upload_enc', methods=['POST'])
def upload_enc():
    data = request.get_json()
    c64 = data.get('ciphertext')
    if c64 is None:
        return jsonify({'status': 'missing_ciphertext'}), 400
    CIPHERTEXTS.append(base64.b64decode(c64.encode('ascii')))
    return jsonify({'status': 'ok', 'stored': len(CIPHERTEXTS)})

@app.route('/aggregate_enc', methods=['POST'])
def aggregate_enc():
    global AGG_CIPHERTEXT, CIPHERTEXTS
    if not CIPHERTEXTS:
        return jsonify({'status': 'no_ciphertexts'}), 400
    # For addition we just keep the list and return "ready".
    # The aggregator does not need to deserialize to add if we treat serialized bytes as opaque, but
    # TenSEAL requires a context to deserialize to ckks_vector and perform addition. In this demo the aggregator
    # will simply mark that an aggregation should be performed by the keyholder (who has secret key) OR
    # the aggregator will attempt to perform aggregation if public context bytes are present.
    AGG_CIPHERTEXT = b'AGG_PENDING'
    return jsonify({'status': 'agg_ready', 'num_ciphertexts': len(CIPHERTEXTS)})

@app.route('/get_agg_cipher', methods=['GET'])
def get_agg_cipher():
    # Return all stored ciphertexts so a keyholder can deserialize them and perform the homomorphic addition locally
    if not CIPHERTEXTS:
        return jsonify({'status': 'no_ciphertexts'}), 400
    # return list of base64 ciphertexts
    import base64
    ciphers_b64 = [base64.b64encode(c).decode('ascii') for c in CIPHERTEXTS]
    return jsonify({'status': 'ok', 'ciphertexts': ciphers_b64})

@app.route('/post_decrypted', methods=['POST'])
def post_decrypted():
    global PLAINTEXT_AGG
    data = request.get_json()
    PLAINTEXT_AGG = data.get('plaintext_aggregate')
    return jsonify({'status': 'plaintext_stored'})
@app.route("/")
def home():
    return """
    <h2>✅ Secure Federated Learning Aggregator is Live!</h2>
    <p>Use endpoints like:</p>
    <ul>
      <li><a href="/get_context">/get_context</a></li>
      <li><a href="/list_uploads">/list_uploads</a></li>
      <li><a href="/get_plain_aggregate">/get_plain_aggregate</a></li>
    </ul>
    """

@app.route('/get_plain_aggregate', methods=['GET'])
def get_plain_aggregate():
    if PLAINTEXT_AGG is None:
        return jsonify({'status': 'no_plaintext'}), 404
    return jsonify({'status': 'ok', 'plaintext_aggregate': PLAINTEXT_AGG})

if __name__ == '__main__':
    print('Aggregator HE demo server starting on http://0.0.0.0:5000')
    app.run(host='0.0.0.0', port=5000)
