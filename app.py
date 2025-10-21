import json
from flask import Flask, jsonify, render_template, request, send_from_directory
import os
import threading
import packet_handler
import rules_manager
import log_manager
import uuid
import shutil

app = Flask(__name__, static_folder='static')
sniffer_thread = None

# --- Web UI ---
@app.route('/')
def index():
    return render_template('index.html')

# --- API Endpoints for Rule Management ---
@app.route('/api/rules', methods=['GET'])
def get_rules():
    return jsonify(rules_manager.rules)

@app.route('/api/rules', methods=['POST'])
def add_rule():
    new_rule = request.json
    new_rule['rule_id'] = str(uuid.uuid4()) # Assign a unique ID
    rules_manager.rules.append(new_rule)
    rules_manager.save_rules()
    return jsonify(new_rule), 201

@app.route('/api/rules/<string:rule_id>', methods=['PUT'])
def update_rule(rule_id):
    updated_rule_data = request.json
    for i, rule in enumerate(rules_manager.rules):
        if rule.get('rule_id') == rule_id:
            rules_manager.rules[i] = updated_rule_data
            rules_manager.save_rules()
            return jsonify(updated_rule_data)
    return jsonify({"status": "error", "message": "Rule not found"}), 404

@app.route('/api/rules/<string:rule_id>', methods=['DELETE'])
def delete_rule(rule_id):
    for i, rule in enumerate(rules_manager.rules):
        if rule.get('rule_id') == rule_id:
            del rules_manager.rules[i]
            rules_manager.save_rules()
            return jsonify({"status": "success", "message": "Rule deleted"})
    return jsonify({"status": "error", "message": "Rule not found"}), 404

@app.route('/api/rules/import', methods=['POST'])
def import_rules():
    if 'file' not in request.files:
        return jsonify({"status": "error", "message": "No file part"}), 400
    file = request.files['file']
    if file.filename == '':
        return jsonify({"status": "error", "message": "No selected file"}), 400
    if file:
        try:
            new_rules = json.load(file)
            # Optional: add to existing or replace
            # This implementation replaces all current rules
            rules_manager.rules = new_rules
            rules_manager.save_rules()
            return jsonify({"status": "success", "message": f"Imported {len(new_rules)} rules."})
        except Exception as e:
            return jsonify({"status": "error", "message": str(e)}), 500

# --- API Endpoints for Log Management ---
@app.route('/api/logs', methods=['GET'])
def list_log_sessions():
    sessions = log_manager.get_log_sessions()
    return jsonify(sessions)

@app.route('/api/logs/<string:task_id>', methods=['GET'])
def get_log_session_details(task_id):
    details = log_manager.get_log_details(task_id)
    if details is None:
        return jsonify({"status": "error", "message": "Log session not found"}), 404
    return jsonify(details)

@app.route('/api/logs/<string:task_id>', methods=['DELETE'])
def delete_log_session(task_id):
    log_dir = os.path.join(log_manager.LOGS_DIR, task_id)
    if not os.path.isdir(log_dir):
        return jsonify({"status": "error", "message": "Log session not found"}), 404
    try:
        shutil.rmtree(log_dir)
        return jsonify({"status": "success", "message": f"Log session {task_id} deleted."})
    except Exception as e:
        return jsonify({"status": "error", "message": str(e)}), 500

# --- API Endpoints for Sniffer Control ---
@app.route('/api/control/start', methods=['POST'])
def start_sniffing_api():
    global sniffer_thread
    if sniffer_thread and sniffer_thread.is_alive():
        return jsonify({"status": "error", "message": "Sniffer is already running."}), 400
    
    log_manager.start_new_log_session() # Start a new log session
    sniffer_thread = threading.Thread(target=packet_handler.start_sniffing, daemon=True)
    sniffer_thread.start()
    return jsonify({"status": "success", "message": "Packet sniffer started."})

@app.route('/api/control/stop', methods=['POST'])
def stop_sniffing_api():
    global sniffer_thread
    if not sniffer_thread or not sniffer_thread.is_alive():
        return jsonify({"status": "error", "message": "Sniffer is not running."}), 400
        
    packet_handler.stop_sniffing_handler()
    sniffer_thread.join(timeout=5) # Wait for the thread to finish
    sniffer_thread = None
    return jsonify({"status": "success", "message": "Packet sniffer stopped."})

if __name__ == '__main__':
    # Use '0.0.0.0' to be accessible from the network
    app.run(host='0.0.0.0', port=5000, debug=True)
