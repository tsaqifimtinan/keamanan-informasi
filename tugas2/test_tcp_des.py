# Test script for DES TCP communication
import socket
import json
import time
import threading

def test_client():
	"""Test function that sends requests to the server"""
	time.sleep(2)  # Wait for server to start
	
	print("\n[TEST] Starting client test...")
	
	try:
		client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		client_socket.connect(('localhost', 8888))
		
		# Test encryption
		encrypt_request = {
			'operation': 'ENCRYPT',
			'plaintext': '123456ABCD132536',
			'key': 'AABB09182736CCDD'
		}
		
		print("[TEST] Sending encryption request...")
		client_socket.send(json.dumps(encrypt_request).encode('utf-8'))
		
		response = client_socket.recv(4096).decode('utf-8')
		encrypt_response = json.loads(response)
		
		print(f"[TEST] Encryption result: {encrypt_response}")
		
		if encrypt_response['status'] == 'success':
			ciphertext = encrypt_response['ciphertext']
			
			# Test decryption
			decrypt_request = {
				'operation': 'DECRYPT',
				'plaintext': ciphertext,
				'key': 'AABB09182736CCDD'
			}
			
			print("[TEST] Sending decryption request...")
			client_socket.send(json.dumps(decrypt_request).encode('utf-8'))
			
			response = client_socket.recv(4096).decode('utf-8')
			decrypt_response = json.loads(response)
			
			print(f"[TEST] Decryption result: {decrypt_response}")
			
			if decrypt_response['status'] == 'success':
				if decrypt_response['plaintext'] == encrypt_request['plaintext']:
					print("[TEST] ✓ SUCCESS: Encryption/Decryption test passed!")
				else:
					print("[TEST] ✗ FAILED: Decrypted text doesn't match original!")
			else:
				print(f"[TEST] ✗ Decryption failed: {decrypt_response['message']}")
		else:
			print(f"[TEST] ✗ Encryption failed: {encrypt_response['message']}")
		
		client_socket.close()
		
	except Exception as e:
		print(f"[TEST] Error: {e}")

if __name__ == "__main__":
	print("=" * 60)
	print("DES TCP COMMUNICATION TEST")
	print("=" * 60)
	print("This script will:")
	print("1. Start a DES server on localhost:8888")
	print("2. Send test encryption/decryption requests")
	print("3. Verify the results")
	print("=" * 60)
	
	# Import server module
	try:
		from des_server import start_server
		
		# Start server in a separate thread
		server_thread = threading.Thread(target=start_server, daemon=True)
		server_thread.start()
		
		print("[TEST] Server started...")
		
		# Run client test
		test_client()
		
		print("\n[TEST] Test completed. Press Ctrl+C to exit.")
		
		# Keep main thread alive
		try:
			while True:
				time.sleep(1)
		except KeyboardInterrupt:
			print("\n[TEST] Shutting down...")
			
	except ImportError:
		print("[ERROR] Could not import des_server. Make sure des_server.py exists.")
	except Exception as e:
		print(f"[ERROR] {e}")