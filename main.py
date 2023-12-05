from flask import Flask, request, jsonify
import json
import hashlib
import time

app = Flask(__name__)

# User and channel data
users = []
channels = []
messages = []

class Block:
    def __init__(self, index, previous_hash, timestamp, data, hash):
        self.index = index
        self.previous_hash = previous_hash
        self.timestamp = timestamp
        self.data = data
        self.hash = hash

def calculate_hash(index, previous_hash, timestamp, data):
    value = str(index) + str(previous_hash) + str(timestamp) + str(data)
    return hashlib.sha256(value.encode()).hexdigest()

def create_genesis_block():
    # Manually create the first block (genesis block)
    return Block(0, "0", time.time(), "Genesis Block", calculate_hash(0, "0", time.time(), "Genesis Block"))

def create_new_block(index, previous_hash, data):
    timestamp = time.time()
    hash = calculate_hash(index, previous_hash, timestamp, data)
    print("------------------------------------------------------")
    print(index)
    print(previous_hash)
    print(timestamp)
    print(data)
    print(hash)
    print("------------------------------------------------------")
    return Block(index, previous_hash, timestamp, data, hash)

class Blockchain:
    def __init__(self):
        self.chain = [create_genesis_block()]
        self.difficulty = 4  # Number of leading zeros required in the hash

    def add_block(self, data):
        index = len(self.chain)
        previous_hash = self.chain[-1].hash
        new_block = create_new_block(index, previous_hash, data)
        proof = self.proof_of_work(new_block)
        self.chain.append(new_block)

    def proof_of_work(self, block):
        block.nonce = 0
        computed_hash = calculate_hash(block.index, block.previous_hash, block.timestamp, str(block.data) + str(block.nonce))

        while not computed_hash.startswith('0' * self.difficulty):
            block.nonce += 1
            computed_hash = calculate_hash(block.index, block.previous_hash, block.timestamp, str(block.data) + str(block.nonce))
            # print(computed_hash)
        return computed_hash

    def add_message_to_blockchain(self, message):
        self.add_block(message)

# Create the blockchain outside of the main application block
blockchain = Blockchain()

# Helper function to authenticate users
def authenticate(username, password):
    return next((user for user in users if user['username'] == username and user['password'] == password), None)

# Helper function to authenticate users and check if they are in the specified channel
def authenticate_channel(username, password, channel_name):
    user = authenticate(username, password)
    channel = next((channel for channel in channels if channel['channel_name'] == channel_name), None)

    if user and channel and username in channel['users']:
        return True

    return False

# Main landing page
@app.route('/')
def homepage():
    return jsonify({'message': 'server is working'})

# Get users in the account
@app.route('/list_users')
def user_list():
    return jsonify(users)

# Get channel names
@app.route('/list_channel')
def list_channel():
    return jsonify(channels)

# Endpoint for user registration
@app.route('/register', methods=['POST'])
def register():
    if request.method == "POST":
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400

        # Check if the username is already taken
        if any(user['username'] == username for user in users):
            return jsonify({'error': 'Username already exists'}), 400

        user = {'username': username, 'password': password}
        users.append(user)

        return jsonify({'message': 'Registration successful'}), 201
    else:
        return jsonify({'message': 'Method not allowed'}), 405

# Endpoint for user login
@app.route('/login', methods=['POST'])
def login():
    if request.method == "POST":
        data = request.json
        username = data.get('username')
        password = data.get('password')

        if not username or not password:
            return jsonify({'error': 'Username and password are required'}), 400

        # Check if the username and password match a registered user
        user = next((user for user in users if user['username'] == username and user['password'] == password), None)

        if not user:
            return jsonify({'error': 'Invalid username or password'}), 401

        return jsonify({'message': 'Login successful'}), 200
    else:
        return jsonify({'message': 'Method not allowed'}), 405

# Endpoint for creating a channel
@app.route('/create_channel', methods=['POST'])
def create_channel():
    if request.method == 'POST':
        data = request.json
        channel_name = data.get('channel_name')

        if not channel_name:
            return jsonify({'error': 'Channel name is required'}), 400

        # Check if the channel name is already taken
        if any(channel['channel_name'] == channel_name for channel in channels):
            return jsonify({'error': 'Channel name already exists'}), 400

        channel = {'channel_name': channel_name, 'users': []}
        channels.append(channel)

        return jsonify({'message': 'Channel created successfully'}), 201
    else:
        return jsonify({'message': 'Method not allowed'}), 405

# Endpoint for joining a channel
@app.route('/join_channel', methods=['POST'])
def join_channel():
    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        channel_name = data.get('channel_name')

        if not username or not channel_name:
            return jsonify({'error': 'Username and channel name are required'}), 400

        # Check if the user is already in the channel
        user = next((user for user in users if user['username'] == username), None)
        channel = next((channel for channel in channels if channel['channel_name'] == channel_name), None)

        if not user or not channel:
            return jsonify({'error': 'User or channel not found'}), 404

        # Add the user to the channel
        channel['users'].append(username)

        return jsonify({'message': f'{username} joined {channel_name}'}), 200
    else:
        return jsonify({'message': 'Method not allowed'})

# Endpoint for sending a new message
@app.route('/send_message', methods=['POST'])
def send_message():
    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')
        channel_name = data.get('channel_name')
        content = data.get('content')

        if not username or not password or not channel_name or not content:
            return jsonify({'error': 'Username, password, channel name, and content are required'}), 400

        # Authenticate user and check if they are in the specified channel
        if not authenticate_channel(username, password, channel_name):
            return jsonify({'error': 'Authentication failed or user not in the channel'}), 401

        # Store the message in the blockchain
        blockchain.add_message_to_blockchain({'username': username, 'channel_name': channel_name, 'content': content})

        # Print the updated blockchain
        messages.append({'username': username, 'channel_name': channel_name, 'content': content})

        return jsonify({'message': 'Message sent successfully'}), 200
    else:
        return jsonify({'message': 'Method not allowed'}), 405

# Endpoint for retrieving messages
@app.route('/get_messages', methods=['POST'])
def get_messages():
    if request.method == 'POST':
        data = request.json
        username = data.get('username')
        password = data.get('password')
        channel_name = data.get('channel_name')

        if not username or not password or not channel_name:
            return jsonify({'error': 'Username, password, and channel name are required'}), 400

        # Authenticate user and check if they are in the specified channel
        if not authenticate_channel(username, password, channel_name):
            return jsonify({'error': 'Authentication failed or user not in the channel'}), 401

        # Retrieve messages for the specified channel
        # channel_messages = [message for message in messages if message['channel_name'] == channel_name]
        channel_messages = []
        for block in blockchain.chain:
            if isinstance(block.data, dict):
                print(block.data)
                channel_messages.append(block.data)

        return jsonify({'messages': channel_messages}), 200
    else:
        return jsonify({'message': 'Method not allowed'})


if __name__ == '__main__':
    app.run(debug=True)
