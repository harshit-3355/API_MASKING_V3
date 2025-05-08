from flask import Flask, request, jsonify, Response
import requests
import base64
import json
import random
import string

app = Flask(__name__)

cached_rows = []

def random_password(length=12):
    safe_chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(random.choices(safe_chars, k=length))

@app.route('/generate_all', methods=['GET'])
def generate_all():
    try:
        base_url = "https://ciparthenon-api.azurewebsites.net/apiRequest?account=demo&route=table/841492"
        api_version = "2021.08"
        limit = 1000
        offset = 0
        rows = []

        # Handle pagination
        while True:
            paged_url = f"{base_url}?limit={limit}&offset={offset}&api_version={api_version}"
            res = requests.get(paged_url)
            res.raise_for_status()
            batch = res.json().get("data", [])
            if not batch:
                break
            rows.extend(batch)
            offset += len(batch)

        print(f"🔄 Total rows fetched: {len(rows)}")

        base_uri_to_row = {}
        for row in rows:
            base_uri = row.get("BASE_URI")
            if base_uri:
                base_uri_to_row[base_uri] = row

        update_data_list = []
        global cached_rows
        cached_rows = []

        base_application_url = request.host_url.rstrip('/')
        client_credentials = {}

        for row in rows:
            client = row.get("CLIENT", "public")
            if all([
                row.get("ADMIN_USERNAME"),
                row.get("ADMIN_PASSWORD"),
                row.get("PUBLIC_USERNAME"),
                row.get("PUBLIC_PASSWORD")
            ]):
                client_credentials[client] = {
                    "ADMIN_USERNAME": row["ADMIN_USERNAME"],
                    "ADMIN_PASSWORD": row["ADMIN_PASSWORD"],
                    "PUBLIC_PASSWORD": row["PUBLIC_PASSWORD"]
                }

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

            client = row.get("CLIENT", "public")

            if client not in client_credentials:
                admin_username = "admin_" + ''.join(random.choices(string.ascii_lowercase, k=6))
                admin_password = random_password()
                public_password = random_password()

                while public_password == admin_password:
                    public_password = random_password()

                client_credentials[client] = {
                    "ADMIN_USERNAME": admin_username,
                    "ADMIN_PASSWORD": admin_password,
                    "PUBLIC_PASSWORD": public_password
                }

            creds = client_credentials[client]
            parameter = row.get("PARAMETER")
            updated_uri = f"{base_application_url}/demo/{parameter}" if parameter else ""

            new_data = {
                "BASE_URI": base_uri,
                "UPDATED_URI": updated_uri,
                "ADMIN_USERNAME": creds["ADMIN_USERNAME"],
                "ADMIN_PASSWORD": creds["ADMIN_PASSWORD"],
                "PUBLIC_USERNAME": client,
                "PUBLIC_PASSWORD": creds["PUBLIC_PASSWORD"],
                "PARAMETER": parameter,
                "CLIENT": client
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


def update_table_data(data_list):
    account_name = 'demo'
    table_id = '841492'
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

@app.route('/demo/<parameter>', methods=['GET'])
def proxy(parameter):
    try:
        auth = request.headers.get("Authorization")
        if not auth or not auth.startswith("Basic "):
            return Response(
                "Authentication required", 401,
                {"WWW-Authenticate": 'Basic realm="Login Required"'}
            )

        encoded_credentials = auth.split(" ")[1]
        decoded_credentials = base64.b64decode(encoded_credentials).decode()
        username, password = decoded_credentials.split(":", 1)

        global cached_rows
        if not cached_rows:
            read_url = "https://ciparthenon-api.azurewebsites.net/apiRequest?account=demo&route=table/841492?api_version=2021.08"
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

        matched_row = next((r for r in cached_rows if r.get("PARAMETER") == parameter), None)
        if not matched_row:
            return jsonify({"error": f"No matching PARAMETER {parameter} found"}), 404

        is_admin = (username == matched_row["ADMIN_USERNAME"] and password == matched_row["ADMIN_PASSWORD"])
        is_public = (username == matched_row["PUBLIC_USERNAME"] and password == matched_row["PUBLIC_PASSWORD"])

        if not (is_admin or is_public):
            return Response(
                "Invalid credentials", 401,
                {"WWW-Authenticate": 'Basic realm="Login Required"'}
            )

        target_uri = matched_row.get("BASE_URI")
        res = requests.get(target_uri)
        res.raise_for_status()

        full_data = res.json()
        query_params = request.args.to_dict()

        if isinstance(full_data, dict) and "data" in full_data:
            original_records = full_data["data"]
            filtered_data = []
            for record in original_records:
                match = True
                for key, value in query_params.items():
                    allowed_values = [v.strip().lower() for v in value.split(",")]
                    record_value = str(record.get(key, "")).strip().lower()
                    if record_value not in allowed_values:
                        match = False
                        break
                if match:
                    filtered_data.append(record)

            final_response = {"data": filtered_data}
        else:
            final_response = full_data

        return jsonify(final_response)

    except Exception as e:
        return jsonify({"error": str(e)}), 500

if __name__ == '__main__':
    app.run(debug=True)
