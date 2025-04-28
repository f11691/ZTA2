import time
import logging
import psutil
import os
import uuid
import requests
from flask import Flask, request, jsonify

app = Flask(__name__)

class PolicyEngine:
    def __init__(self, fsm, risk_assessment_url, pa_url):
        self.fsm = fsm  # FSM instance
        self.risk_assessment_url = risk_assessment_url  # URL of Risk Assessment module
        self.pa_url = pa_url  # URL of Policy Administration module
        self.policies = {}  # Local cache of policies
        self.setup_logging()

    def setup_logging(self):
        # Configure the logging module
        logging.basicConfig(
            filename='policy_engine.log',
            level=logging.INFO,
            format='%(asctime)s %(levelname)s: %(message)s'
        )

    def policy_updated(self, entity_id, policy_data, request_id):
        self.policies[entity_id] = policy_data
        logging.info(f"Request ID: {request_id} | PE: Policy for entity '{entity_id}' updated from PA.")

    def get_policy(self, entity_id, request_id):
        # Retrieve the policy for the entity from PA
        try:
            response = requests.get(f'{self.pa_url}/get_policy', params={'entity_id': entity_id, 'request_id': request_id})
            response.raise_for_status()
            data = response.json()
            policy = data.get('policy', {})
            self.policies[entity_id] = policy  # Update local cache
            logging.info(f"Request ID: {request_id} | PE: Policy for entity '{entity_id}' fetched from PA.")
            return policy
        except Exception as e:
            logging.error(f"Request ID: {request_id} | PE Error: Failed to fetch policy for entity '{entity_id}' from PA: {e}")
            return {}

    def receive_risk_update(self, entity_id, risk_level, request_id):
        """
        Handle risk updates pushed by the Risk Assessment module.
        """
        # Start CPU and timing measurements
        process = psutil.Process(os.getpid())
        cpu_times_start = process.cpu_times()
        start_time = time.time()

        # Map risk level to FSM event
        event = self.map_risk_level_to_event(risk_level)

        # Trigger the event in FSM
        new_state, decision = self.fsm.trigger_event(entity_id, event)

        logging.info(f"Request ID: {request_id} | PE: Entity '{entity_id}' state updated to '{new_state}' due to risk level '{risk_level}'.")

        # Notify PA of the state change
        self.notify_pa_state_update(entity_id, new_state, request_id)

        # End CPU and timing measurements
        end_time = time.time()
        cpu_times_end = process.cpu_times()

        # Calculate CPU time and processing time
        user_cpu_time = cpu_times_end.user - cpu_times_start.user
        system_cpu_time = cpu_times_end.system - cpu_times_start.system
        total_cpu_time = user_cpu_time + system_cpu_time
        processing_time = end_time - start_time

        # Log the performance data
        logging.info(
            f"Request ID: {request_id} | Entity ID: {entity_id} | Risk Level: {risk_level} | "
            f"Processing Time: {processing_time:.6f}s | CPU Time: User={user_cpu_time:.6f}s "
            f"System={system_cpu_time:.6f}s Total={total_cpu_time:.6f}s"
        )

    def process_access_request(self, entity_id, resource_id, profile_status, request_id):
        """
        Handle access requests from the PEP.
        """
        # Start CPU and timing measurements
        process = psutil.Process(os.getpid())
        cpu_times_start = process.cpu_times()
        start_time = time.time()

        # Get the current state of the entity
        current_state = self.fsm.get_state(entity_id)

        # Get risk status from Risk Assessment module
        risk_level = self.get_risk_status(entity_id, request_id)

        # Determine if an event needs to be triggered based on risk level
        event = self.determine_event(risk_level, profile_status, entity_id)
        logging.info(f"Event: {event}")
        # Trigger the event in FSM if necessary
        if event != 'no_event':
            new_state, decision = self.fsm.trigger_event(entity_id, event)
            logging.info(f"Request ID: {request_id} | PE: Entity '{entity_id}' state updated to '{new_state}' due to event '{event}'.")
            # Notify PA of the state change
            self.notify_pa_state_update(entity_id, new_state, request_id)
        else:
            new_state = current_state
        logging.info(f"State: {new_state}")
        # Make an access decision based on the new state and policies
        access_decision = self.make_access_decision(entity_id, new_state, resource_id, request_id)

        # End CPU and timing measurements
        end_time = time.time()
        cpu_times_end = process.cpu_times()

        # Calculate CPU time and processing time
        user_cpu_time = cpu_times_end.user - cpu_times_start.user
        system_cpu_time = cpu_times_end.system - cpu_times_start.system
        total_cpu_time = user_cpu_time + system_cpu_time
        processing_time = end_time - start_time

        # Log the performance data
        logging.info(
            f"Request ID: {request_id} | Entity ID: {entity_id} | Access Decision: {access_decision} | "
            f"Processing Time: {processing_time:.6f}s | CPU Time: User={user_cpu_time:.6f}s "
            f"System={system_cpu_time:.6f}s Total={total_cpu_time:.6f}s"
        )

        return access_decision

    def determine_event(self, risk_level, profile_status, entity_id):
        # Logic to determine the FSM event based on risk level and profile status
        if profile_status == 'unauthenticated':
            return 'contact_lost'
        elif risk_level == 'critical':
            return 'critical_threat_detected'
        elif risk_level == 'high risk':
            return 'significant_issue_detected'
        elif risk_level == 'low risk':
            return 'minor_anomaly_detected'
        elif risk_level == 'normal' and self.fsm.get_state(entity_id) != 'Normal':
            return 'anomaly_resolved'
        else:
            return 'no_event'  # No state change needed

    def map_risk_level_to_event(self, risk_level):
        # Map risk level to FSM event
        if risk_level == 'critical':
            return 'critical_threat_detected'
        elif risk_level == 'high risk':
            return 'significant_issue_detected'
        elif risk_level == 'low risk':
            return 'minor_anomaly_detected'
        elif risk_level == 'normal':
            return 'anomaly_resolved'
        else:
            return 'no_event'

    def make_access_decision(self, entity_id, state, resource_id, request_id):
        """
        Makes an access decision based on the entity's state, policy, and requested resource.
        """
        policy = self.get_policy(entity_id, request_id)
        access_level = policy.get('access_level', 'no-access')
        allowed_resources = policy.get('allowed_resources', [])
        restricted_resources = policy.get('restricted_resources', [])
    
        # If entity is quarantined, deny access
        if state == 'Quarantined':
            return 'deny'
        if state == 'Normal':
            return 'allow'
    
        # Check if resource is restricted
        if resource_id in restricted_resources:
            return 'deny'
    
        # Check if resource is allowed
        if resource_id not in allowed_resources and allowed_resources:
            return 'deny'
    
        # Check access level
        if access_level == 'no-access':
            return 'deny'
        elif access_level == 'read-only':
            # Further checks or restrictions can be added here
            return 'allow'
        elif access_level == 'full':
            return 'allow'
        else:
            return 'deny'

    def notify_pa_state_update(self, entity_id, new_state, request_id):
        # Notify the PA of the state change
        try:
            payload = {
                'entity_id': entity_id,
                'new_state': new_state,
                'request_id': request_id
            }
            response = requests.post(f'{self.pa_url}/receive_state_update', json=payload)
            response.raise_for_status()
            logging.info(f"Request ID: {request_id} | PE: Notified PA of state update for entity '{entity_id}' to '{new_state}'.")
        except Exception as e:
            logging.error(f"Request ID: {request_id} | PE Error: Failed to notify PA of state update: {e}")

    def get_risk_status(self, entity_id, request_id):
        # Request risk status from Risk Assessment module
        try:
            payload = {
                'entity_id': entity_id,
                'request_id': request_id
            }
            response = requests.post(f'{self.risk_assessment_url}/get_risk_status', json=payload)
            response.raise_for_status()
            data = response.json()
            risk_level = data.get('risk_level', 'normal')
            logging.info(f"Request ID: {request_id} | PE: Risk level for entity '{entity_id}' is '{risk_level}'.")
            return risk_level
        except Exception as e:
            logging.error(f"Request ID: {request_id} | PE Error: Failed to get risk status for entity '{entity_id}': {e}")
            return 'normal'  # Default to 'normal' if unable to get risk status

# Flask API Endpoints

PE_instance = None  # Will be initialized later

@app.route('/process_access_request', methods=['POST'])
def process_access_request_endpoint():
    """
    API endpoint to process access requests from PEP.
    Expects JSON data with 'entity_id', 'resource_id', 'profile_status', 'request_id'.
    """
    try:
        json_data = request.get_json()
        entity_id = json_data.get('entity_id')
        resource_id = json_data.get('resource_id')
        profile_status = json_data.get('profile_status')
        request_id = json_data.get('request_id', str(uuid.uuid4()))

        access_decision = PE_instance.process_access_request(entity_id, resource_id, profile_status, request_id)

        response = {
            'request_id': request_id,
            'access_decision': access_decision
        }
        return jsonify(response), 200
    except Exception as e:
        logging.error(f"Error in process_access_request_endpoint: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/policy_updated', methods=['POST'])
def policy_updated_endpoint():
    """
    API endpoint for PA to notify PE of policy updates.
    Expects JSON data with 'entity_id', 'policy_data', 'request_id'.
    """
    try:
        json_data = request.get_json()
        entity_id = json_data.get('entity_id')
        policy_data = json_data.get('policy_data', {})
        request_id = json_data.get('request_id', str(uuid.uuid4()))

        PE_instance.policy_updated(entity_id, policy_data, request_id)

        response = {
            'request_id': request_id,
            'status': 'Policy updated successfully'
        }
        return jsonify(response), 200
    except Exception as e:
        logging.error(f"Error in policy_updated_endpoint: {e}")
        return jsonify({'error': str(e)}), 500

@app.route('/receive_risk_update', methods=['POST'])
def receive_risk_update_endpoint():
    """
    API endpoint for Risk Assessment module to send risk updates to PE.
    Expects JSON data with 'entity_id', 'risk_level', 'request_id'.
    """
    try:
        json_data = request.get_json()
        entity_id = json_data.get('entity_id')
        risk_level = json_data.get('risk_level')
        request_id = json_data.get('request_id', str(uuid.uuid4()))

        PE_instance.receive_risk_update(entity_id, risk_level, request_id)

        response = {
            'request_id': request_id,
            'status': 'Risk update processed successfully'
        }
        return jsonify(response), 200
    except Exception as e:
        logging.error(f"Error in receive_risk_update_endpoint: {e}")
        return jsonify({'error': str(e)}), 500

if __name__ == '__main__':
    # Initialize FSM instance
    from fsm import FSM
    fsm = FSM()

    # Set the URLs of the Risk Assessment module and PA
    risk_assessment_url = 'http://192.52.33.29:5000'  # Replace with actual IP
    pa_url = 'http://192.52.34.155:5000'  # Replace with actual IP

    # Create an instance of PolicyEngine
    PE_instance = PolicyEngine(fsm, risk_assessment_url, pa_url)

    # Run the Flask app on all interfaces, port 5000
    app.run(host='0.0.0.0', port=5000)
