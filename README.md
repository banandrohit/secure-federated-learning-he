# Secure Federated Learning HE Demo (COVID-19 API, Render-ready)

This demo shows a **teaching-oriented** pipeline where multiple clients fetch live COVID-19 data,
compute a tiny update (a 1D linear coefficient), encrypt the update using TenSEAL (CKKS),
upload ciphertexts to an aggregator, and a **keyholder** client decrypts the aggregated result.

This demo is intentionally simplified to demonstrate core ideas:
- Aggregator never has the secret key.
- Clients encrypt with a *public* context (provided by the keyholder).
- The keyholder (a trusted party) holds the secret context locally and performs decryption of the aggregate.
- This is *not* production-ready; real deployments use multiparty keygen / threshold decryption.

## Files in this package
- `aggregator_he.py` — Flask server for receiving public context and ciphertexts.
- `client_he.py` — client/keyholder/decryptor roles. Use to create context, encrypt updates, and decrypt aggregate.
- `requirements.txt` — dependencies.
- `README.md` — this document.

## Quick local test (recommended first)
1. Create a Python virtualenv and install dependencies:
   ```bash
   python -m venv venv
   source venv/bin/activate   # or venv\\Scripts\\activate on Windows
   pip install -r requirements.txt
   ```
   **Note:** `tenseal` requires a C++ build toolchain. If you can't install `tenseal`, you can still run the demo; `client_he.py` will fall back to sending plaintext bytes as a fallback (insecure) so you can test flow.

2. Start the aggregator on machine A (or locally):
   ```bash
   python aggregator_he.py
   ```

3. On machine B run the keyholder to publish the public context (this creates a local secret context file):
   ```bash
   python client_he.py --agg http://<AGG_HOST>:5000 --role keyholder
   ```
   This command creates a `local_secret_context.ctx` file in the keyholder's working directory — **keep it secret**.

4. On each client machine run (after step 3):
   ```bash
   python client_he.py --agg http://<AGG_HOST>:5000 --role client
   ```
   Each client will fetch live COVID-19 summary data from `https://api.covid19api.com/summary`,
   compute a small update vector (1D coefficient), encrypt it with the server's public context, and upload ciphertext.

5. After clients have uploaded ciphertexts, the aggregator provides them via `/get_agg_cipher`.
   The **keyholder** (who saved `local_secret_context.ctx`) should run:
   ```bash
   python client_he.py --agg http://<AGG_HOST>:5000 --role decryptor
   ```
   This fetches ciphertexts, deserializes and sums/averages them using the secret key, decrypts the result,
   and posts the plaintext back to the aggregator. Clients can then poll `/get_plain_aggregate` to fetch the plaintext aggregate.

## Deploying the aggregator to Render.com
Render is a simple way to host the aggregator.
1. Push this repository to GitHub.
2. Create an account at https://render.com and create a new **Web Service**.
   - Connect your GitHub repo and select the branch.
   - Set the build command to `pip install -r requirements.txt`
   - Set the start command to `python aggregator_he.py`
3. Render will expose a public HTTPS URL; use that as `--agg` when running `client_he.py` from remote machines:
   ```bash
   python client_he.py --agg https://<your-render-url> --role keyholder
   python client_he.py --agg https://<your-render-url> --role client
   ```

## Important notes & limitations
- **TenSEAL installation on Render**: Render's default environment may not include the build toolchain TenSEAL needs. If `tenseal` fails to install on Render, deploy the aggregator without TenSEAL (it will still accept and store bytes) and run keyholder + decryption locally or on a VM that supports TenSEAL. Another option is to use a cloud VM (AWS EC2 / Lightsail) with build tools preinstalled.
- **Security**: The keyholder must be trusted and must **never** share `local_secret_context.ctx`. For production, use multiparty key generation or a dedicated KMS/HSM and threshold decryption.
- **Data privacy**: This demo fetches public COVID-19 summary data — never use real private patient data without proper infra and approvals.
- **Prod readiness**: Real systems require authentication, HTTPS, replay protection, padding, integrity checks, and careful parameter selection for CKKS (scale, modulus, etc.).

## Questions or help
If you want, I can:
- Produce a small shell script that automates steps 1–5 locally.
- Create a Render-specific `Dockerfile` that installs TenSEAL (may need build tools) and demonstrates a working deploy.
- Convert this demo to a fully-local plaintext + simulated-HE mode for quick experiments.

Which would you like next?
