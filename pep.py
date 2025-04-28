# pep.py

import time
import logging
import os
import uuid
import requests
import csv
from flask import Flask, request, jsonify

app = Flask(__name__)

class PEP:
    def __init__(self, pe_url, authenticator_url, pa_url, pep_url):
        self.pe_url = pe_url
        self.authenticator_url = authenticator_url
        self.pa_url = pa_url
        self.pep_url = pep_url  # URL where this PEP is accessible
        self.banned_ids = set()
        self.request_counts = {}  # Track request counts per entity
        self.last_reset_time = time.time()  # Track when counters were last reset
        self.request_threshold = 30  # Max requests allowed per window (example value)
        self.window_seconds = 10  # Window size in seconds
        self.setup_logging()
        self.setup_csv_logging()
        # Register with PA
        self.register_with_pa()

    def setup_logging(self):
        logging.basicConfig(
            filename='pep.log',
            level=logging.INFO,
            format='%(asctime)s %(levelname)s: %(message)s'
        )

    def setup_csv_logging(self):
        self.csv_file = open('pep_requests.csv', 'a', newline='')
        self.csv_writer = csv.writer(self.csv_file)
        if os.stat('pep_requests.csv').st_size == 0:
            self.csv_writer.writerow([
                'Request ID', 'Timestamp', 'Sender', 'Destination Entity',
                'Processing Time (s)', 'CPU Time (s)', 'CPU Consumption (%)'
            ])

    def register_with_pa(self):
        try:
            payload = {
                'pep_url': self.pep_url,
                'request_id': str(uuid.uuid4())
            }
            response = requests.post(f'{self.pa_url}/register_pep', json=payload)
            response.raise_for_status()
            logging.info(f"PEP: Registered with PA at '{self.pa_url}'.")
        except Exception as e:
            logging.error(f"PEP Error: Failed to register with PA: {e}")

    def update_banned_ids(self, banned_ids):
        self.banned_ids = set(banned_ids)
        logging.info(f"PEP: Updated banned IDs list: {self.banned_ids}")

    def handle_request(self, entity_id, resource_id, request_data, request_id):
        logging.info(f"Request ID: {request_id} | PEP: Received request from '{entity_id}' for resource '{resource_id}'")

        # Anti-DoS Check
        current_time = time.time()
        if current_time - self.last_reset_time > self.window_seconds:
            self.request_counts.clear()
            self.last_reset_time = current_time

        self.request_counts[entity_id] = self.request_counts.get(entity_id, 0) + 1

        if self.request_counts[entity_id] > self.request_threshold:
            logging.warning(f"Request ID: {request_id} | PEP: Entity '{entity_id}' exceeded allowed request rate. Blocking temporarily.")
            self.deny_access(entity_id, resource_id, request_data, request_id)

            try:
                anomaly_payload = {
                    'entity_id': entity_id,
                    'attack_type': 'data_flooding',
                    'confidence': 95,
                    'request_id': request_id
                }
                requests.post('http://192.52.33.29:5000/record_anomaly', json=anomaly_payload)
            except Exception as e:
                logging.error(f"Failed to notify Risk Assessment about data flooding: {e}")

            return 'deny'

        # Authenticate the entity
        auth_status = self.authenticate_entity(entity_id, request_data, request_id)
        logging.info(f"Request ID: {request_id} | PEP: Entity '{entity_id}' authentication status: {auth_status}")

        if entity_id in self.banned_ids:
            logging.warning(f"Request ID: {request_id} | PEP: Entity '{entity_id}' is banned. Rejecting request.")
            self.deny_access(entity_id, resource_id, request_data, request_id)
            return 'deny'

        access_decision = self.process_access_request(entity_id, resource_id, auth_status, request_id)

        if access_decision == 'allow':
            self.allow_access(entity_id, resource_id, request_data, request_id)
        else:
            self.deny_access(entity_id, resource_id, request_data, request_id)

        return access_decision

    def authenticate_entity(self, entity_id, request_data, request_id):
        try:
            payload = {
                'entity_id': entity_id,
                'request_data': request_data,
                'request_id': request_id
            }
            response = requests.post(f'{self.authenticator_url}/authenticate', json=payload)
            response.raise_for_status()
            auth_data = response.json()
            return auth_data.get('authentication_status', 'unauthenticated')
        except Exception as e:
            logging.error(f"Request ID: {request_id} | PEP Error: Failed to authenticate entity '{entity_id}': {e}")
            return 'unauthenticated'

    def process_access_request(self, entity_id, resource_id, profile_status, request_id):
        try:
            payload = {
                'entity_id': entity_id,
                'resource_id': resource_id,
                'profile_status': profile_status,
                'request_id': request_id
            }
            response = requests.post(f'{self.pe_url}/process_access_request', json=payload)
            response.raise_for_status()
            data = response.json()
            return data.get('access_decision', 'deny')
        except Exception as e:
            logging.error(f"Request ID: {request_id} | PEP Error: Failed to process access request for entity '{entity_id}': {e}")
            return 'deny'

    def allow_access(self, entity_id, resource_id, request_data, request_id):
        logging.info(f"Request ID: {request_id} | PEP: Access granted to '{entity_id}' for resource '{resource_id}'")

    def deny_access(self, entity_id, resource_id, request_data, request_id):
        logging.info(f"Request ID: {request_id} | PEP: Access denied to '{entity_id}' for resource '{resource_id}'")

    def log_request(self, request_id, sender, destination, processing_time, cpu_time, cpu_consumption):
        timestamp = time.strftime('%Y-%m-%d %H:%M:%S')
        self.csv_writer.writerow([
            request_id, timestamp, sender, destination,
            f"{processing_time:.6f}", f"{cpu_time:.6f}", f"{cpu_consumption:.2f}%"
        ])
        self.csv_file.flush()

    def __del__(self):
        self.csv_file.close()

# Flask API Endpoints

PEP_instance = None

@app.route('/handle_request', methods=['POST'])
def handle_request_endpoint():
    try:
        json_data = request.get_json()
        entity_id = json_data.get('entity_id')
        resource_id = json_data.get('resource_id')
        request_data = json_data.get('request_data', {})
        request_id = json_data.get('request_id', str(uuid.uuid4()))

        start_time = time.perf_counter()
        cpu_time_start = time.process_time()

        access_decision = PEP_instance.handle_request(entity_id, resource_id, request_data, request_id)

        end_time = time.perf_counter()
        cpu_time_end = time.process_time()

        total_cpu_time = cpu_time_end - cpu_time_start
        processing_time = end_time - start_time

        if processing_time > 0:
            cpu_consumption = (total_cpu_time / processing_time) * 100
            cpu_consumption = min(cpu_consumption, 100.0)
        else:
            cpu_consumption = 0.0

        PEP_instance.log_request(
            request_id, entity_id, resource_id, processing_time, total_cpu_time, cpu_consumption
        )

        return jsonify({'request_id': request_id, 'access_decision': access_decision}), 200
    except Exception as e:
        logging.error(f"Error in handle_request_endpoint: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/update_banned_ids', methods=['POST'])
def update_banned_ids_endpoint():
    try:
        json_data = request.get_json()
        banned_ids = json_data.get('banned_ids', [])
        PEP_instance.update_banned_ids(banned_ids)
        return jsonify({'status': 'Banned IDs updated successfully'}), 200
    except Exception as e:
        logging.error(f"Error in update_banned_ids_endpoint: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    authenticator_url = 'http://192.52.33.29:5001'
    pe_url = 'http://192.52.33.4:5000'
    pa_url = 'http://192.52.34.155:5000'
    pep_url = 'http://127.0.0.1:5000'

    PEP_instance = PEP(pe_url, authenticator_url, pa_url, pep_url)

    app.run(host='0.0.0.0', port=5000)
