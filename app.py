from flask import Flask, request, jsonify, Response
# from azure.monitor.opentelemetry import configure_azure_monitor
import requests
import base64
import json
import random
import string
import gunicorn
 

# configure_azure_monitor(
#     connection_string="InstrumentationKey=xxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxx;IngestionEndpoint=https://..."
# )

app = Flask(__name__)

cached_rows = []
 
def random_password(length=12):
    safe_chars = string.ascii_letters + string.digits + "!@#$%^&*()-_=+"
    return ''.join(random.choices(safe_chars, k=length))
 
@app.route('/generate_all', methods=['GET'])
def generate_all():
    try:
        base_url = "https://ciparthenon-api.azurewebsites.net/apiRequest?account=demo&route=table/841492?api_version=2021.08"
        
        # Fetch all rows in a single request
        res = requests.get(base_url)
        res.raise_for_status()
        rows = res.json().get("data", [])

        print(f"🔄 Total rows fetched: {len(rows)}")

        client_param_to_row = {}
        client_credentials = {}
        global cached_rows
        cached_rows = []
        update_data_list = []
        base_application_url = request.host_url.rstrip('/')

        # 1. First pass: Find and store credentials for each client if any row has them
        for row in rows:
            client = row.get("CLIENT", "public")
            parameter = row.get("PARAMETER")
            if not client or not parameter:
                continue
            key = (client, parameter)
            client_param_to_row[key] = row

            # If this row has credentials, store them for the client (if not already stored)
            if all([
                row.get("ADMIN_USERNAME"),
                row.get("ADMIN_PASSWORD"),
                row.get("PUBLIC_USERNAME"),
                row.get("PUBLIC_PASSWORD")
            ]):
                if client not in client_credentials:
                    client_credentials[client] = {
                        "ADMIN_USERNAME": row["ADMIN_USERNAME"],
                        "ADMIN_PASSWORD": row["ADMIN_PASSWORD"],
                        "PUBLIC_USERNAME": row["PUBLIC_USERNAME"],
                        "PUBLIC_PASSWORD": row["PUBLIC_PASSWORD"]
                    }

        # 2. Second pass: Generate credentials for clients that don't have any
        for (client, parameter), row in client_param_to_row.items():
            already_set = all([
                row.get("UPDATED_URI"),
                row.get("PUBLIC_USERNAME"),
                row.get("PUBLIC_PASSWORD"),
                row.get("ADMIN_USERNAME"),
                row.get("ADMIN_PASSWORD")
            ])
            if already_set:
                print(f"✅ Already set, skipping BASE_URI: {row['BASE_URI']}")
                cached_rows.append(row)
                continue

            # If client doesn't have credentials, generate and store them
            if client not in client_credentials:
                print(f"🔐 Generating credentials for client: {client}")
                admin_username = "admin_" + ''.join(random.choices(string.ascii_lowercase, k=6))
                admin_password = random_password()
                public_username = client  # Use client as public username
                public_password = random_password()
                while public_password == admin_password:
                    public_password = random_password()
                client_credentials[client] = {
                    "ADMIN_USERNAME": admin_username,
                    "ADMIN_PASSWORD": admin_password,
                    "PUBLIC_USERNAME": public_username,
                    "PUBLIC_PASSWORD": public_password
                }

            creds = client_credentials[client]

            updated_uri = f"{base_application_url}/{client}/{parameter}"
            new_data = {
                "BASE_URI": row["BASE_URI"],
                "UPDATED_URI": updated_uri,
                "ADMIN_USERNAME": creds["ADMIN_USERNAME"],
                "ADMIN_PASSWORD": creds["ADMIN_PASSWORD"],
                "PUBLIC_USERNAME": creds["PUBLIC_USERNAME"],
                "PUBLIC_PASSWORD": creds["PUBLIC_PASSWORD"],
                "PARAMETER": parameter,
                "CLIENT": client
            }

            print(f"🆕 Adding to update list: BASE_URI={row['BASE_URI']}, PARAMETER={parameter}")
            update_data_list.append(new_data)
            cached_rows.append(new_data)

        if update_data_list:
            print(f"📤 Updating {len(update_data_list)} row(s) in table.")
            update_table_data(update_data_list)
        else:
            print("🚫 No rows to update.")

        return jsonify({
            "inserted": update_data_list,
            "note": "Refresh skipped — table is not refreshable."
        })

    except Exception as e:
        print(f"❌ Exception in /generate_all: {str(e)}")
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
                            },
                            {
                                "name": "CLIENT",
                                "comparator": "equals",
                                "values": [data["CLIENT"]]
                            },
                            {
                                "name": "PARAMETER",
                                "comparator": "equals",
                                "values": [data["PARAMETER"]]
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
                print(f"✅ Updated BASE_URI {data['BASE_URI']} for CLIENT {data['CLIENT']} PARAMETER {data['PARAMETER']}")
            else:
                print(f"❌ Failed to update {data['BASE_URI']} for CLIENT {data['CLIENT']} PARAMETER {data['PARAMETER']}: {response.status_code}, {response.text}")
        except Exception as e:
            print(f"❌ Exception for {data['BASE_URI']} (CLIENT {data['CLIENT']} PARAMETER {data['PARAMETER']}):", str(e))
 
@app.route('/<client>/<parameter>', methods=['GET'])
def proxy(client, parameter):
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
 
        matched_row = next(
            (r for r in cached_rows if r.get("CLIENT") == client and r.get("PARAMETER") == parameter),
            None
        )
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
 
        # New unified logic
        original_records = []
 
        if isinstance(full_data, dict) and "data" in full_data:
            original_records = full_data["data"]
        elif isinstance(full_data, list):
            original_records = full_data
 
        # If we have filter params, apply them
        if query_params and original_records:
            query = {k: [v.strip() for v in val.split(",")] for k, val in query_params.items()}
 
            filtered_data = []
            for record in original_records:
                match = True
                for key, values in query.items():
                    record_val = str(record.get(key, "")).strip()
                    if record_val not in values:
                        match = False
                        break
                if match:
                    filtered_data.append(record)
 
            final_response = {"data": filtered_data}
        else:
            # If no filtering or data not found, return original as-is
            final_response = {"data": original_records} if isinstance(original_records, list) else full_data
 
 
 
        return jsonify(final_response)
 
    except Exception as e:
        return jsonify({"error": str(e)}), 500
 
@app.after_request
def set_csp_headers(response):
    response.headers['Content-Security-Policy'] = "default-src 'none';"
    response.headers['X-Content-Type-Options'] = "nosniff"
    response.headers['Cache-Control'] = "no-store"
    return response
 
if __name__ == '__main__':
    app.run(debug=False, threaded=True)
 