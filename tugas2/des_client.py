# DES Client - Sends encryption/decryption requests to server
import socket
import json

def validate_hex_input(data, length):
	if len(data) != length:
		return False, f"Must be exactly {length} hexadecimal characters"
	
	valid_hex_chars = set('0123456789ABCDEF')
	if not all(c in valid_hex_chars for c in data.upper()):
		return False, "Contains invalid hexadecimal characters"
	
	return True, "Valid"

def send_request(host, port, operation, data, key):
	try:
		# Create socket and connect to server
		client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		client_socket.connect((host, port))
		
		# Prepare request
		request = {
			'operation': operation,
			'plaintext': data,
			'key': key
		}
		
		# Send request
		request_json = json.dumps(request)
		client_socket.send(request_json.encode('utf-8'))
		
		# Receive response
		response_data = client_socket.recv(4096).decode('utf-8')
		response = json.loads(response_data)
		
		client_socket.close()
		return response
	
	except ConnectionRefusedError:
		return {
			'status': 'error',
			'message': f'Cannot connect to server at {host}:{port}. Make sure the server is running.'
		}
	except Exception as e:
		return {
			'status': 'error',
			'message': f'Connection error: {str(e)}'
		}

def main():
	print("=" * 60)
	print("DES ENCRYPTION/DECRYPTION CLIENT")
	print("=" * 60)
	print("This client connects to a DES server for encryption/decryption.")
	print("Please enter your data in hexadecimal format (0-9, A-F).")
	print("Both data and key must be exactly 16 hex characters (64 bits).")
	print("=" * 60)
	print()
	
	# Server connection details
	host = input("Enter server IP address (press Enter for localhost): ").strip()
	if not host:
		host = 'localhost'
	
	try:
		port = input("Enter server port (press Enter for 8888): ").strip()
		if not port:
			port = 8888
		else:
			port = int(port)
	except ValueError:
		print("Invalid port number. Using default port 8888.")
		port = 8888
	
	print(f"\nConnecting to server at {host}:{port}")
	print()
	
	while True:
		try:
			# Get operation
			print("Choose operation:")
			print("1. ENCRYPT")
			print("2. DECRYPT")
			print("3. EXIT")
			
			choice = input("Enter your choice (1/2/3): ").strip()
			
			if choice == '3':
				print("Goodbye!")
				break
			
			if choice not in ['1', '2']:
				print("Invalid choice. Please enter 1, 2, or 3.")
				continue
			
			operation = 'ENCRYPT' if choice == '1' else 'DECRYPT'
			
			# Get input data
			if operation == 'ENCRYPT':
				data = input("Enter plaintext (16 hex characters): ").strip().upper()
			else:
				data = input("Enter ciphertext (16 hex characters): ").strip().upper()
			
			# Get key
			key = input("Enter key (16 hex characters): ").strip().upper()
			
			# Validate inputs
			valid_data, data_msg = validate_hex_input(data, 16)
			valid_key, key_msg = validate_hex_input(key, 16)
			
			if not valid_data:
				print(f"Error - Data: {data_msg}")
				continue
			
			if not valid_key:
				print(f"Error - Key: {key_msg}")
				continue
			
			# Send request to server
			print(f"\nSending {operation} request to server...")
			response = send_request(host, port, operation, data, key)
			
			# Display response
			print("\n" + "=" * 50)
			print("SERVER RESPONSE")
			print("=" * 50)
			
			if response['status'] == 'success':
				print(f"✓ Operation: {response['operation'].upper()}")
				if operation == 'ENCRYPT':
					print(f"  Plaintext:  {response['plaintext']}")
					print(f"  Key:        {response['key']}")
					print(f"  Ciphertext: {response['ciphertext']}")
				else:
					print(f"  Ciphertext: {response['ciphertext']}")
					print(f"  Key:        {response['key']}")
					print(f"  Plaintext:  {response['plaintext']}")
				print("✓ SUCCESS: Operation completed successfully!")
			else:
				print(f"✗ ERROR: {response['message']}")
			
			print("=" * 50)
			print()
			
		except KeyboardInterrupt:
			print("\nGoodbye!")
			break
		except Exception as e:
			print(f"Unexpected error: {e}")

if __name__ == "__main__":
	main()