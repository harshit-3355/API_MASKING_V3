from flask import Flask, request, jsonify, Response
from cryptography.fernet import Fernet
import requests
import urllib.parse
import random
import string
import base64
import json

app = Flask(__name__)

cached_rows = []
def random_username(prefix):
    return f"{prefix}_{''.join(random.choices(string.ascii_lowercase, k=6))}"

def random_password(length=12):
    safe_chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(random.choices(safe_chars, k=length))

@app.route('/generate_all', methods=['GET'])
def generate_all():
    try:
        read_url = "https://ciparthenon-api.azurewebsites.net/apiRequest?account=demo&route=table/841280?api_version=2021.08"
        res = requests.get(read_url)
        res.raise_for_status()
        rows = res.json().get("data", [])

        base_uri_to_row = {}
        for row in rows:
            base_uri = row.get("BASE_URI")
            if base_uri:
                base_uri_to_row[base_uri] = row

        update_data_list = []
        global cached_rows
        cached_rows = []

        for base_uri, row in base_uri_to_row.items():
            already_set = all([
                row.get("UPDATED_URI"),
                row.get("PUBLIC_USERNAME"),
                row.get("PUBLIC_PASSWORD"),
                row.get("ADMIN_USERNAME"),
                row.get("ADMIN_PASSWORD")
            ])
            if already_set:
                cached_rows.append(row)
                continue

            # 🔐 Generate encrypted URI
            key = Fernet.generate_key()
            fernet = Fernet(key)
            encrypted_token = fernet.encrypt(base_uri.encode()).decode()
            token_param = urllib.parse.quote(encrypted_token)
            key_param = urllib.parse.quote(key.decode())
            updated_uri = f"{request.host_url}demo?token={token_param}&key={key_param}"

            # 🔧 New credentials
            new_data = {
                "BASE_URI": base_uri,
                "UPDATED_URI": updated_uri,
                "ADMIN_USERNAME": random_username("admin"),
                "ADMIN_PASSWORD": "713SRo3y",
                "PUBLIC_USERNAME": random_username("user"),
                "PUBLIC_PASSWORD": random_password()
            }

            update_data_list.append(new_data)
            cached_rows.append(new_data)

        if update_data_list:
            update_table_data(update_data_list)

        return jsonify({
            "inserted": update_data_list,
            "note": "Refresh skipped — table is not refreshable."
        })

    except Exception as e:
        return jsonify({"error": str(e)}), 500


# 🔄 JS-Style Update Payload
def update_table_data(data_list):
    account_name = 'demo'
    table_id = '841280'
    update_url = f"https://ciparthenon-api.azurewebsites.net/apiRequest?account={account_name}&route=data/{table_id}/update?api_version=2022.01"

    for data in data_list:
        payload = {
            "multiple_rows": "all",
            "data": {
                "UPDATED_URI": data["UPDATED_URI"],
                "ADMIN_USERNAME": data["ADMIN_USERNAME"],
                "ADMIN_PASSWORD": data["ADMIN_PASSWORD"],
                "PUBLIC_USERNAME": data["PUBLIC_USERNAME"],
                "PUBLIC_PASSWORD": data["PUBLIC_PASSWORD"]
            },
            "filter": {
                "condition": [
                    {
                        "columns": [
                            {
                                "name": "BASE_URI",
                                "comparator": "equals",
                                "values": [data["BASE_URI"]]
                            }
                        ],
                        "operator": "and"
                    }
                ]
            }
        }

        try:
            response = requests.post(
                update_url,
                headers={'Content-Type': 'application/json'},
                data=json.dumps(payload)
            )

            if response.ok:
                print(f"✅ Updated BASE_URI {data['BASE_URI']}")
            else:
                print(f"❌ Failed to update {data['BASE_URI']}: {response.status_code}, {response.text}")
        except Exception as e:
            print(f"❌ Exception for {data['BASE_URI']}:", str(e))


@app.route('/demo', methods=['GET'])
def proxy():
    try:
        token = request.args.get("token")
        key = request.args.get("key")
        if not token or not key:
            return jsonify({"error": "Missing token or key"}), 400

        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Basic "):
            return Response(
                "Authentication required", 401,
                {"WWW-Authenticate": 'Basic realm="Login Required"'}
            )

        encoded_credentials = auth.split(" ")[1]
        decoded_credentials = base64.b64decode(encoded_credentials).decode()
        username, password = decoded_credentials.split(":", 1)

        decrypted_uri = Fernet(key.encode()).decrypt(urllib.parse.unquote(token).encode()).decode()

        global cached_rows
        if not cached_rows:
            # Fallback load in case /generate_all wasn't called
            read_url = "https://ciparthenon-api.azurewebsites.net/apiRequest?account=demo&route=table/841280?api_version=2021.08"
            res = requests.get(read_url)
            res.raise_for_status()
            rows = res.json().get("data", [])
            cached_rows = [r for r in rows if all([
                r.get("BASE_URI"),
                r.get("UPDATED_URI"),
                r.get("PUBLIC_USERNAME"),
                r.get("PUBLIC_PASSWORD"),
                r.get("ADMIN_USERNAME"),
                r.get("ADMIN_PASSWORD")
            ])]
        
        matched_row = next((r for r in cached_rows if r["BASE_URI"] == decrypted_uri), None)
        if not matched_row:
            return jsonify({"error": "Matching BASE_URI not found"}), 404

        is_admin = (username == matched_row["ADMIN_USERNAME"] and password == matched_row["ADMIN_PASSWORD"])
        is_public = (username == matched_row["PUBLIC_USERNAME"] and password == matched_row["PUBLIC_PASSWORD"])

        if not (is_admin or is_public):
            return Response(
                "Invalid credentials", 401,
                {"WWW-Authenticate": 'Basic realm="Login Required"'}
            )

        res = requests.get(decrypted_uri)
        res.raise_for_status()
        full_data = res.json()

        if is_admin:
            return jsonify(full_data)
        else:
            return jsonify(full_data)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
