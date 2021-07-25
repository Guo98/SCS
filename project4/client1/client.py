import requests
# TODO: import additional modules as required
import os
from base64 import b64encode
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
import glob
import os.path
import simplejson as json
import shutil

gt_username = 'aguo43'   # TODO: Replace with your gt username within quotes
server_name = 'secure-shared-store'

''' <!!! DO NOT MODIFY THIS FUNCTION !!!>'''
def post_request(server_name, action, body, node_certificate, node_key):
	'''
		node_certificate is the name of the certificate file of the client node (present inside certs).
		node_key is the name of the private key of the client node (present inside certs).
		body parameter should in the json format.
	'''
	request_url= 'https://{}/{}'.format(server_name,action)
	request_headers = {
		'Content-Type': "application/json"
		}
	response = requests.post(
		url= request_url,
		data=json.dumps(body),
		headers = request_headers,
		cert = (node_certificate, node_key),
	)
	with open(gt_username, 'wb') as f:
		f.write(response.content)
	return response

''' You can begin modification from here'''
def login(uid, key_filename):
	'''
		# TODO: Accept the
		 - user-id
		 - name of private key file(should be
		present in the userkeys folder) of the user.
		Generate the login statement as given in writeup and its signature.
		Send request to server with required parameters (action = 'login') using
		post_request function given.
		The request body should contain the user-id, statement and signed statement.
	'''
	cwd = os.getcwd()
	client_name = cwd.split('/')[-1]
	login_statement = str(client_name + ' as ' + uid + ' logs into the server')
	print("heres the statement: " + login_statement)

	# open private key and sign
	if os.path.exists('userkeys/' + key_filename) == False:
		return ''
	private_key = RSA.importKey(open('userkeys/' + key_filename).read())
	digest = SHA256.new(login_statement.encode("utf-8"))
	signature = pkcs1_15.new(private_key).sign(digest)

	body = {
		'user-id': b64encode(uid.encode("utf-8")),
		'statement': b64encode(login_statement.encode("utf-8")),
		'signature': b64encode(signature)
	}
	print("before")
	response = post_request(server_name, 'login', body, 'certs/' + client_name + '.crt', 'certs/' + client_name + '.key')
	print("response: " + str(response))
	resp = response.json()
	session_token = ''
		
	if resp['status'] == 200:
		session_token = resp['session_token']
		files = glob.glob('documents/checkout/*')
		for f in files:
			os.remove(f)

	print("whats the session token: " + session_token)
	return session_token

def checkin(document_id, security_flag, user_id, session_token):
	'''
		# TODO: Accept the
		 - DID
		 - security flag (1 for confidentiality  and 2 for integrity)
		Send the request to server with required parameters (action = 'checkin') using post_request().
		The request body should contain the required parameters to ensure the file is sent to the server.
	'''
	cwd = os.getcwd()
	client_name = cwd.split('/')[-1]

	if os.path.exists('documents/checkin/' + document_id) == False:
		if os.path.exists('documents/checkout/' + document_id) == True:
			os.rename('documents/checkout/' + document_id, 'documents/checkin/' + document_id)
		else:
			return ''

	with open('documents/checkin/' + document_id) as f: 
		content = f.read()

	body = {
		'user-id': b64encode(user_id.encode("utf-8")),
		'doc-id': b64encode(document_id.encode("utf-8")),
		'file-content': b64encode(content.encode("utf-8")),
		'security-flag': b64encode(security_flag.encode("utf-8")),
		'session-token': b64encode(session_token.encode("utf-8"))
	}
	
	resp = post_request(server_name, 'checkin', body, 'certs/' + client_name + '.crt', 'certs/' + client_name + '.key').json()
	session_token = resp['session_token']
	print(resp['message'])
	return session_token

def checkout(doc_id, user_id, session_token):
	'''
		# TODO: Accept the DID.
		Send request to server with required parameters (action = 'checkout') using post_request()
	'''
	cwd = os.getcwd()
	client_name = cwd.split('/')[-1]
	body = {
		'user-id': b64encode(user_id.encode("utf-8")),
		'doc-id': b64encode(doc_id.encode("utf-8")),
		'session-token': b64encode(session_token.encode("utf-8"))
	}

	resp = post_request(server_name, 'checkout', body, 'certs/' + client_name + '.crt', 'certs/' + client_name + '.key').json()
	session_token = resp['session_token']
	if resp['status'] == 200:
		if os.path.exists('documents/checkout/' + doc_id) == True:
			os.remove('documents/checkout/' + doc_id)
		with open('documents/checkout/' + doc_id, 'w') as f:
			f.write(resp['file_content'])
		print(resp['message'])
	else:
		print(resp['message'])
	return session_token

def grant(did, tuid, right, dur, uid, stoken):
	'''
		# TODO: Accept the
		 - DID
		 - target user to whom access should be granted (0 for all user)
		 - type of acess to be granted (1 - checkin, 2 - checkout, 3 - both checkin and checkout)
		 - time duration (in seconds) for which acess is granted
		Send request to server with required parameters (action = 'grant') using post_request()
	'''
	cwd = os.getcwd()
	client_name = cwd.split('/')[-1]
	body = {
		'user-id': b64encode(uid.encode("utf-8")),
		'doc-id': b64encode(did.encode("utf-8")),
		'session-token': b64encode(stoken.encode("utf-8")),
		'tuid': b64encode(tuid.encode("utf-8")),
		'right': b64encode(right.encode("utf-8")),
		'time': b64encode(dur.encode("utf-8"))
	}
	resp = post_request(server_name, 'grant', body, 'certs/' + client_name + '.crt', 'certs/' + client_name + '.key').json()
	session_token = resp['session_token']
	print(resp['message'])
	return session_token

def delete(did, uid, session_token):
	'''
		# TODO: Accept the DID to be deleted.
		Send request to server with required parameters (action = 'delete')
		using post_request().
	'''
	cwd = os.getcwd()
	client_name = cwd.split('/')[-1]
	body = {
		'user-id': b64encode(uid.encode("utf-8")),
		'doc-id': b64encode(did.encode("utf-8")),
		'session-token': b64encode(session_token.encode("utf-8"))
	}
	resp = post_request(server_name, 'delete', body, 'certs/' + client_name + '.crt', 'certs/' + client_name + '.key').json()
	session_token = resp['session_token']
	print(resp['message'])
	return session_token

def logout(uid, session_token):
	'''
		# TODO: Ensure all the modified checked out documents are checked back in.
		Send request to server with required parameters (action = 'logout') using post_request()
		The request body should contain the user-id, session-token
	'''
	cwd = os.getcwd()
	client_name = cwd.split('/')[-1]
	body = {
		'user-id': b64encode(uid.encode("utf-8")),
		'session-token': b64encode(session_token.encode("utf-8"))
	}
	resp = post_request(server_name, 'logout', body, 'certs/' + client_name + '.crt', 'certs/' + client_name + '.key').json()
	session_token = resp['session_token']
	print(resp['message'])
	exit() #exit the program

def main():
	'''
		# TODO: Authenticate the user by calling login.
		If the login is successful, provide the following options to the user
			1. Checkin
			2. Checkout
			3. Grant
			4. Delete
			5. Logout
		The options will be the indices as shown above. For example, if user
		enters 1, it must invoke the Checkin function. Appropriate functions
		should be invoked depending on the user input. Users should be able to
		perform these actions in a loop until they logout. This mapping should 
		be maintained in your implementation for the options.
	'''
	# initial login
	user_id = input("Enter your user id: ")
	private_key_path = input("Enter your private key file name: ")
	
	session_token = login(user_id, private_key_path)

	# if login was unsuccessful, try again
	while session_token == '':
		login_again = input("Login unsuccessful. Do you want to try again? (y/n)")
		if login_again == 'y' or login_again == 'Y':
			user_id = input("Enter your user id: ")
			private_key_path = input("Enter your private key file name: ")
	
			session_token = login(user_id, private_key_path)
		else:
			break
	print("Login successful!\n")

	if session_token == '':
		print("Login unsuccessful.\n")
		return
	# check session token
	while session_token != '':
		print("1. Checkin (Document Id, Security Flag)\n2. Checkout (Document Id)\n3. Grant (Document Id, Target User Id, Access Right, Time)\n4. Delete (Document Id)\n5. Logout")
		option = input("Select option: ")
		if option == '1':
			doc_id = input("Enter the document id you want to check in: ")
			security_flag = input("Enter the security flag you want for the document (1 = Confidentiality or 2 = Integrity): ")
			session_token = checkin(doc_id, security_flag, user_id, session_token)
		elif option == '2':
			doc_id = input("Enter the document id you want to check out: ")
			session_token = checkout(doc_id, user_id, session_token)
		elif option == '3':
			doc_id = input("Enter the document id you want to grant access to: ")
			tuid = input("Enter the user id of who you want to grant access to: ")
			right = input("Enter the access right (1 = Checkin, 2 = Checkout, 3 = Both) you want to grant: ")
			time = input("Enter duration in seconds: ")
			session_token = grant(doc_id, tuid, right, time, user_id, session_token)
		elif option == '4':
			doc_id = input("Enter the document id you want to delete: ")
			session_token = delete(doc_id, user_id, session_token)
		elif option == '5':
			logout(user_id, session_token)
		else:
			print("Invalid option")
			return
	
	return
if __name__ == '__main__':
	main()
