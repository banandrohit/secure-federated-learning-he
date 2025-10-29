# aggregator_he.py
# Flask server that receives encrypted updates (TenSEAL ciphertexts serialized)
# Stores public context bytes (no secret key) to allow ciphertext deserialization for addition.
# Aggregator does NOT hold secret keys and therefore cannot decrypt.

from flask import Flask, request, jsonify
import base64, os

app = Flask(__name__)
app.config['MAX_CONTENT_LENGTH'] = 1000 * 1024 * 1024  # 20 MB limit

# In-memory storage (for demo)
PUBLIC_CONTEXT_BYTES = None
CIPHERTEXTS = []
PLAINTEXT_AGG = None

# -----------------------------
# Initialization
# -----------------------------
@app.route('/init_public_context', methods=['POST'])
def init_public_context():
    """Receive and store the public TenSEAL context (no secret key)."""
    global PUBLIC_CONTEXT_BYTES
    data = request.get_json()
    ctx_b64 = data.get('context')
    if not ctx_b64:
        return jsonify({'status': 'error', 'msg': 'missing context'}), 400

    # ✅ store in memory and save to file
    PUBLIC_CONTEXT_BYTES = base64.b64decode(ctx_b64.encode('ascii'))
    with open('public_context.ctx', 'wb') as f:
        f.write(PUBLIC_CONTEXT_BYTES)

    return jsonify({'status': 'public_context_saved'})

@app.route('/get_public_context', methods=['GET'])
def get_public_context():
    if PUBLIC_CONTEXT_BYTES is None:
        return jsonify({'status': 'no_context'}), 404
    return jsonify({'context': base64.b64encode(PUBLIC_CONTEXT_BYTES).decode('ascii')})

@app.route('/get_context', methods=['GET'])
def get_context_alias():
    return get_public_context()

# -----------------------------
# Uploads and aggregation
# -----------------------------
@app.route('/upload_enc', methods=['POST'])
def upload_enc():
    data = request.get_json()
    c64 = data.get('ciphertext')
    if not c64:
        return jsonify({'status': 'missing_ciphertext'}), 400
    CIPHERTEXTS.append(base64.b64decode(c64.encode('ascii')))
    return jsonify({'status': 'ok', 'stored': len(CIPHERTEXTS)})

@app.route('/aggregate_enc', methods=['POST'])
def aggregate_enc():
    if not CIPHERTEXTS:
        return jsonify({'status': 'no_ciphertexts'}), 400
    # For demo, we don't aggregate server-side (keyholder does it)
    return jsonify({'status': 'agg_ready', 'num_ciphertexts': len(CIPHERTEXTS)})

@app.route('/get_agg_cipher', methods=['GET'])
def get_agg_cipher():
    if not CIPHERTEXTS:
        return jsonify({'status': 'no_ciphertexts'}), 400
    ciphers_b64 = [base64.b64encode(c).decode('ascii') for c in CIPHERTEXTS]
    return jsonify({'status': 'ok', 'ciphertexts': ciphers_b64})

@app.route('/post_decrypted', methods=['POST'])
def post_decrypted():
    global PLAINTEXT_AGG
    data = request.get_json()
    PLAINTEXT_AGG = data.get('plaintext_aggregate')
    return jsonify({'status': 'plaintext_stored'})

# -----------------------------
# Utility / info routes
# -----------------------------
@app.route("/")
def home():
    return """
    <h2>✅ Secure Federated Learning Aggregator is Live!</h2>
    <p>Use endpoints like:</p>
    <ul>
      <li><a href="/get_context">/get_context</a></li>
      <li><a href="/get_plain_aggregate">/get_plain_aggregate</a></li>
      <li><a href="/ping">/ping</a></li>
    </ul>
    """

@app.route('/get_plain_aggregate', methods=['GET'])
def get_plain_aggregate():
    if PLAINTEXT_AGG is None:
        return jsonify({'status': 'no_plaintext'}), 404
    return jsonify({'status': 'ok', 'plaintext_aggregate': PLAINTEXT_AGG})

@app.route('/ping')
def ping():
    return jsonify({'status': 'ok', 'message': 'Aggregator is running!'})

# -----------------------------
# Entry point
# -----------------------------
if __name__ == '__main__':
    port = int(os.environ.get('PORT', 5000))
    print(f'🚀 Aggregator HE demo server starting on port {port}...')
    app.run(host='0.0.0.0', port=port)
