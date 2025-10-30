from flask import Flask, render_template, request, redirect, flash
import hashlib
import json
import os
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization

app = Flask(__name__)
app.secret_key = "supersecretkey"

DATA_FILE = "blockchain_data.json"
blockchain = []

# --- Load blockchain data from file ---
def load_blockchain():
    global blockchain
    if os.path.exists(DATA_FILE):
        with open(DATA_FILE, "r") as f:
            blockchain = json.load(f)
    else:
        blockchain = []

# --- Save blockchain data to file ---
def save_blockchain():
    with open(DATA_FILE, "w") as f:
        json.dump(blockchain, f, indent=4)

def calculate_hash(block):
    block_string = json.dumps(block, sort_keys=True).encode()
    return hashlib.sha256(block_string).hexdigest()

def add_block(land_data):
    block = {
        "index": len(blockchain) + 1,
        "data": land_data,
        "previous_hash": blockchain[-1]["hash"] if blockchain else "0"
    }
    block["hash"] = calculate_hash(block)
    blockchain.append(block)
    save_blockchain()

# --- Generate public/private key pair ---
def generate_key_pair():
    private_key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.TraditionalOpenSSL,
        encryption_algorithm=serialization.NoEncryption()
    ).decode()

    public_pem = private_key.public_key().public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    ).decode()

    return public_pem, private_pem

@app.route('/')
def index():
    return render_template('register.html')

@app.route('/register_land', methods=['POST'])
def register_land():
    owner_name = request.form['owner_name']
    area = request.form['area']
    location = request.form['location']

    owner_pubkey, owner_privkey = generate_key_pair()

    for block in blockchain:
        if block["data"]["owner_name"] == owner_name and block["data"]["location"] == location:
            flash("❌ Land already registered by this owner at this location.")
            return redirect('/')

    land_data = {
        "land_id": len(blockchain) + 1,
        "owner_name": owner_name,
        "area": area,
        "location": location,
        "owner_pubkey": owner_pubkey,
        "owner_privkey": owner_privkey
    }

    add_block(land_data)
    flash("✅ Land registered successfully! Keys generated below:")
    flash(f"🔑 Public Key:\n{owner_pubkey}")
    flash(f"🔐 Private Key:\n{owner_privkey}")

    return redirect('/')

@app.route('/view_land', methods=['GET', 'POST'])
def view_land():
    found_lands = []
    if request.method == 'POST':
        pubkey = request.form['public_key'].replace("\r", "").replace("\n", "").replace(" ", "").strip()
        for block in blockchain:
            stored_key = block["data"]["owner_pubkey"].replace("\r", "").replace("\n", "").replace(" ", "").strip()
            if stored_key == pubkey:
                found_lands.append(block["data"])
    return render_template('view_land.html', lands=found_lands)


@app.route('/all_lands')
def view_all():
    all_lands = [block["data"] for block in blockchain]
    return render_template('view_all.html', lands=all_lands)

if __name__ == '__main__':
    load_blockchain()
    app.run(debug=True)
