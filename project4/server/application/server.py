from flask import Flask, request, jsonify
from flask_restful import Resource, Api
# TODO: import additional modules as required
from uuid import uuid4
from base64 import b64decode, b64encode
from Crypto.Hash import SHA256
from Crypto.PublicKey import RSA
from Crypto.Signature import pkcs1_15
from Crypto.Cipher import AES, PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto import Random
import os.path
import os
from tinydb import TinyDB, Query
import random
import simplejson as json
import base64
from datetime import datetime, timedelta

secure_shared_service = Flask(__name__)
api = Api(secure_shared_service)

class welcome(Resource):
	def get(self):
		return "Welcome to the secure shared server!"

class login(Resource):
	def post(self):
		data = request.get_json()
		# TODO: Implement login functionality
		'''
		# TODO: Verify the signed statement.
			Response format for success and failure are given below. The same
			keys ('status', 'message', 'session_token') should be used.
		'''
		user_id = b64decode(data['user-id'])
		statement = b64decode(data['statement'])
		signature = b64decode(data['signature'])
		print("userid: " + str(user_id))
		# check statement
		digest = SHA256.new(statement)

		public_key = RSA.importKey(open('userpublickeys/' + user_id.decode("utf-8") + '.pub').read())
		try:
			pkcs1_15.new(public_key).verify(digest, signature)
			success = True
		except:
			success = False

		if success:
			session_token = str(uuid4()) # TODO: Generate session token
			print("server session token: " + session_token)
			# Similar response format given below can be used for all the other functions
			response = {
				'status': 200,
				'message': 'Login Successful',
				'session_token': session_token,
			}
		else:
			response = {
				'status': 700,
				'message': 'Login Failed'
			}

		db_file_exists = os.path.exists('db_docs.json')
		
		if db_file_exists == False:
			with open('db_docs.json', 'w') as outfile:
				pass
		return jsonify(response)

class checkout(Resource):
	def post(self):
		data = request.get_json()
		# TODO: Implement checkout functionality

		user_id = b64decode(data['user-id']).decode("utf-8")
		doc_id = b64decode(data['doc-id']).decode("utf-8")
		session_token = b64decode(data['session-token']).decode("utf-8")

		# check if document exists
		db = TinyDB('db_docs.json')
		documents = Query()

		query_result = db.search(documents.did == doc_id)
		if len(query_result) == 0:
			response = {
				'status': 704,
				'message': 'Check out failed since file not found on the server',
				'session_token': session_token
			}
			return jsonify(response)
		success = False
		broken = False
		nexist = False
		access_denied = False
		sflag = str(query_result[0]['flag'])
		try:
			if str(query_result[0]['uid']) == user_id:
				if sflag == "1":
					file_content = self.decrypt(doc_id, query_result[0]['enc_key'], query_result[0]['iv'])
					if file_content == 'Nonexistent':
						nexist = True
					elif file_content == 'Failed':
						success = False
					else:
						success = True
				elif sflag == "2":
					file_content = self.verify(doc_id)
					if file_content != False and file_content != 'Invalid signature' and file_content != 'Nonexistent':
						success = True
					elif file_content == 'Invalid signature':
						broken = True
					elif file_content == 'Nonexistent':
						nexist = True
			elif user_id in str(query_result[0]['2']) or user_id in str(query_result[0]['3']):
				expire_time = datetime.strptime(str(query_result[0][user_id+'-time']), '%H:%M:%S')
				if datetime.now().time() >= expire_time.time():
					if user_id in str(query_result[0]['2']):
						ulist = str(query_result[0]['2']).split(',')
						for u in ulist:
							if u == user_id:
								ulist.remove(u)
								newlist = ','.join(ulist)
								break
						db.update({'2': newlist}, documents.did == doc_id)
					elif user_id in str(query_result[0]['3']):
						ulist = str(query_result[0]['3']).split(',')
						for u in ulist:
							if u == user_id:
								ulist.remove(u)
								newlist = ','.join(ulist)
								break
						db.update({'3': newlist}, documents.did == doc_id)
					response = {
						'status': 702,
						'message': 'Access denied to check in',
						'session_token': session_token
					}
					return jsonify(response)
				else:
					if sflag == "1":
						file_content = self.decrypt(doc_id, query_result[0]['enc_key'], query_result[0]['iv'])
						if file_content == 'Nonexistent':
							nexist = True
						elif file_content == 'Failed':
							success = False
						else:
							success = True
					elif sflag == "2":
						file_content = self.verify(doc_id)
						if file_content != False and file_content != 'Invalid signature' and file_content != 'Nonexistent':
							success = True
						elif file_content == 'Invalid signature':
							broken = True
						elif file_content == 'Nonexistent':
							nexist = True
			elif  '0' in str(query_result[0]['2']) or '0' in str(query_result[0]['3']):
				expire_time = datetime.strptime(str(query_result[0]['0-time']), '%H:%M:%S')
				if datetime.now().time() >= expire_time.time():
					if '0' in str(query_result[0]['2']):
						ulist = str(query_result[0]['2']).split(',')
						for u in ulist:
							if u == '0':
								ulist.remove(u)
								newlist = ','.join(ulist)
								break
						db.update({'2': newlist}, documents.did == doc_id)
					elif '0' in str(query_result[0]['3']):
						ulist = str(query_result[0]['3']).split(',')
						for u in ulist:
							if u == '0':
								ulist.remove(u)
								newlist = ','.join(ulist)
								break
						db.update({'3': newlist}, documents.did == doc_id)
					response = {
						'status': 702,
						'message': 'Access denied to check in',
						'session_token': session_token
					}
					return jsonify(response)
				else:
					if sflag == "1":
						file_content = self.decrypt(doc_id, query_result[0]['enc_key'], query_result[0]['iv'])
						if file_content == 'Nonexistent':
							nexist = True
						elif file_content == 'Failed':
							success = False
						else:
							success = True
					elif sflag == "2":
						file_content = self.verify(doc_id)
						if file_content != False and file_content != 'Invalid signature' and file_content != 'Nonexistent':
							success = True
						elif file_content == 'Invalid signature':
							broken = True
						elif file_content == 'Nonexistent':
							nexist = True
			else:
				access_denied = True
		except:
			success = False
			broken = False
			nexist = False
			access_denied = False
		response = ''
		if success == True:
			response = {
				'status': 200,
				'message': 'Document Successfully checked out',
				'file_content': file_content,
				'session_token': session_token
			}
		elif broken == True:
			response = {
				'status': 703,
				'message': 'Check out failed due to broken integrity',
				'session_token': session_token
			}
		elif nexist == True:
			response = {
				'status': 704,
				'message': 'Check out failed since file not found on the server',
				'session_token': session_token
			}
		elif access_denied == True:
			response = {
				'status': 702,
				'message': 'Access denied to check out',
				'session_token': session_token
			}
		else:
			response = {
				'status': 700,
				'message': 'Other failures',
				'session_token': session_token
			}

			
		return jsonify(response)
	'''
		Expected response status codes
		1) 200 - Document Successfully checked out
		2) 702 - Access denied to check out
		3) 703 - Check out failed due to broken integrity
		4) 704 - Check out failed since file not found on the server
		5) 700 - Other failures
	'''

	def decrypt(self, did, enc_key, iv):
		if os.path.exists('documents/' + did) == False:
			return 'Nonexistent'
		public_key = RSA.importKey(open('../certs/secure-shared-store.key').read())
		cipher_rsa = PKCS1_OAEP.new(public_key)
		
		ekey = base64.b64decode(enc_key.encode('utf-8'))
		iv_dec = base64.b64decode(iv.encode('utf-8'))
		decrypted_key = cipher_rsa.decrypt(ekey)

		enc_content =''
		with open('documents/' + did, 'rb') as efile:
			enc_content = efile.read()
		try:
			aes = AES.new(decrypted_key, AES.MODE_CFB, iv_dec)
			file_content = aes.decrypt(enc_content)
		except:
			return 'Failed'
		return	file_content.decode("utf-8")

	def verify(self, did):
		public_key = RSA.importKey(open('../certs/secure-shared-store.pub').read())
		if os.path.exists('documents/' + did) == False or os.path.exists('documents/signed-' + did) == False:
			return 'Nonexistent'
		with open('documents/' + did, 'rb') as ofile:
			file_c = ofile.read()
		digest = SHA256.new(file_c)
		with open('documents/signed-' + did, 'rb') as sfile:
			signature = sfile.read()
		try:
			pkcs1_15.new(public_key).verify(digest, signature)
			return file_c.decode("utf-8")
		except:
			return 'Invalid signature'
			
		return False
class checkin(Resource):
	def post(self):
		data = request.get_json()
		# TODO: Implement checkin functionality

		user_id = b64decode(data['user-id']).decode("utf-8")
		file_content = b64decode(data['file-content']).decode("utf-8")
		security_flag = b64decode(data['security-flag']).decode("utf-8")
		doc_id = b64decode(data['doc-id']).decode("utf-8")
		session_token = b64decode(data['session-token']).decode("utf-8")
		
		# check if document exists
		db = TinyDB('db_docs.json')
		documents = Query()

		query_result = db.search(documents.did == doc_id)
		
		if len(query_result) > 0:
			quid = str(query_result[0]['uid'])
			try:
				if quid != user_id and user_id in str(query_result[0]['2']) and '0' in str(query_result[0]['2']):
					response = {
						'status': 702,
						'message': 'Access denied to check in',
						'session_token': session_token
					}
					return jsonify(response)
			except:
				response = {
					'status': 702,
					'message': 'Access denied to check in',
					'session_token': session_token
				}
				return jsonify(response)
			if str(query_result[0]['uid']) == user_id:
				pass
			elif user_id in str(query_result[0]['1']) or user_id in str(query_result[0]['3']):
				expire_time = datetime.strptime(str(query_result[0][user_id+'-time']), '%H:%M:%S')
				if datetime.now().time() >= expire_time.time():
					if user_id in str(query_result[0]['1']):
						ulist = str(query_result[0]['1']).split(',')
						for u in ulist:
							if u == user_id:
								ulist.remove(u)
								newlist = ','.join(ulist)
								break
						db.update({'1': newlist}, documents.did == doc_id)
					else:
						ulist = str(query_result[0]['3']).split(',')
						for u in ulist:
							if u == user_id:
								ulist.remove(u)
								newlist = ','.join(ulist)
								break
						db.update({'3': newlist}, documents.did == doc_id)
					response = {
						'status': 702,
						'message': 'Access denied to check in',
						'session_token': session_token
					}
					return jsonify(response)

			elif '0' in str(query_result[0]['1']) or '0' in str(query_result[0]['3']):
				expire_time = datetime.strptime(str(query_result[0]['0-time']), '%H:%M:%S')
				if datetime.now().time() >= expire_time.time():
					if '0' in str(query_result[0]['1']):
						ulist = str(query_result[0]['1']).split(',')
						for u in ulist:
							if u == '0':
								ulist.remove(u)
								newlist = ','.join(ulist)
								break
						db.update({'1': newlist}, documents.did == doc_id)
					else:
						ulist = str(query_result[0]['3']).split(',')
						for u in ulist:
							if u == '0':
								ulist.remove(u)
								newlist = ','.join(ulist)
								break
						db.update({'3': newlist}, documents.did == doc_id)
					response = {
						'status': 702,
						'message': 'Access denied to check in',
						'session_token': session_token
					}
					return jsonify(response)
		public_key = RSA.importKey(open('../certs/secure-shared-store.pub').read())
		private_key = RSA.importKey(open('../certs/secure-shared-store.key').read())
		success = False
		if security_flag == '1':
			if os.path.exists('documents/' + doc_id) == True:
				os.remove('documents/' + doc_id)

			key = get_random_bytes(32)
			iv = Random.new().read(AES.block_size)
			encrypt = AES.new(key, AES.MODE_CFB, iv)

			with open('documents/' + doc_id, 'wb') as efile:
				efile.write(encrypt.encrypt(file_content.encode("utf-8")))

			# used this site to help with encrypting key https://pycryptodome.readthedocs.io/en/latest/src/examples.html
				
			cipher_rsa = PKCS1_OAEP.new(public_key)
			encrypted_key = cipher_rsa.encrypt(key)	
			row = {
				'did': doc_id,
				'content': file_content,
				'uid': user_id,
				'flag': security_flag,
				'enc_key': base64.b64encode(encrypted_key).decode('utf-8'),
				'iv': base64.b64encode(iv).decode('utf-8'),
				'session_token': session_token
			}			
			if len(query_result) == 0:
				row['1'] = ''
				row['2'] = ''
				row['3'] = ''	
				db.insert(row)
			else:
				db.update(row, documents.did == doc_id)
			success = True
		elif security_flag == '2':
			if os.path.exists('documents/' + doc_id) == True:
				os.remove('documents/' + doc_id)
			if os.path.exists('documents/signed-' + doc_id) == True:
				os.remove('documents/signed-' + doc_id)
			with open('documents/' + doc_id, 'wb') as ofile:
				ofile.write(file_content.encode("utf-8"))
			digest = SHA256.new(file_content.encode("utf-8"))
			with open('documents/signed-' + doc_id, 'wb') as sfile:
				sfile.write(pkcs1_15.new(private_key).sign(digest))
			
			row = {
				'did': doc_id,
				'content': file_content,
				'uid': user_id,
				'flag': security_flag,
				'session_token': session_token
			}
			if len(query_result) == 0:
				row['1'] = ''
				row['2'] = ''
				row['3'] = ''	
				db.insert(row)
			else:
				db.update(row, documents.did == doc_id)
			success = True

		if success == True:
			response = {
				'status': 200,
				'message': 'Checkin successful',
				'session_token': session_token
			}
		elif success == False:
			response = {
				'status': 700,
				'message': 'Checkin unsuccessful',
				'session_token': session_token
			}
		return jsonify(response)
	'''
		Expected response status codes:
		1) 200 - Document Successfully checked in
		2) 702 - Access denied to check in
		3) 700 - Other failures
	'''

class grant(Resource):
	def post(self):
		data = request.get_json()
		# TODO: Implement grant functionality
		uid = b64decode(data['user-id']).decode("utf-8")
		tuid = b64decode(data['tuid']).decode("utf-8")
		right = b64decode(data['right']).decode("utf-8")
		did = b64decode(data['doc-id']).decode("utf-8")
		session_token = b64decode(data['session-token']).decode("utf-8")
		time_seconds = b64decode(data['time']).decode("utf-8")

		db = TinyDB('db_docs.json')
		documents = Query()
		query_result = db.search(documents.did == did)

		if len(query_result) == 0:
			response = {
				'status': 700,
				'message': 'Other failures',
				'session_token': session_token
			}
			return jsonify(response)
		elif str(query_result[0]['uid']) != uid:
			response = {
				'status': 702,
				'message': 'Access denied to grant access',
				'session_token': session_token
			}
			return jsonify(response)
		else:
			try:
				if tuid == '0':
					access_time = datetime.now() + timedelta(seconds = int(time_seconds))
					str_time = '{:%H:%M:%S}'.format(access_time)
					if right == '1':
						db.update({right: '0,', '2': '', '3': ''}, documents.did == did) 
					elif right == '2':
						db.update({right: '0,', '1': '', '3': ''}, documents.did == did) 
					elif right == '3':
						db.update({right: '0,', '2': '', '1': ''}, documents.did == did) 
					else:
						response = {
							'status': 700,
							'message': 'Other failures',
							'session_token': session_token
						}
						return jsonify(response)
				elif right == '1' or right == '2' or right == '3':
					right1 = str(query_result[0]['1'])
					right2 = str(query_result[0]['2'])
					right3 = str(query_result[0]['3'])
					str1 = self.remove(right1, tuid)
					str2 = self.remove(right2, tuid)
					str3 = self.remove(right3, tuid)			

					access_time = datetime.now() + timedelta(seconds = int(time_seconds))
					str_time = '{:%H:%M:%S}'.format(access_time)
					if right == '1':
						str1 = str1 + tuid + ','
						db.update({'1': str1, '2': str2, '3': str3, tuid+'-time': str_time}, documents.did == did)
					elif right == '2':
						str2 = str2 + tuid + ','
						db.update({'1': str1, '2': str2, '3': str3, tuid+'-time': str_time}, documents.did == did)
					elif right == '3':
						str3 = str3 + tuid + ','
						db.update({'1': str1, '2': str2, '3': str3, tuid+'-time': str_time}, documents.did == did)
				else:
					response = {
						'status': 700,
						'message': 'Other failures',
						'session_token': session_token
					}
					return jsonify(response)
			except:
				response = {
					'status': 700,
					'message': 'Other failures',
					'session_token': session_token
				}
				return jsonify(response)

		response = {
			'status': 200,
			'message': 'Successfully granted access',
			'session_token': session_token
		}	
			
		return jsonify(response)
	'''
		Expected response status codes:
		1) 200 - Successfully granted access
		2) 702 - Access denied to grant access
		3) 700 - Other failures
	'''
	def remove(self, ulist, uid):
		rlist = ulist
		if uid in ulist:
			userlist = ulist.split(',')
			for u in userlist:
				if u == uid:
					userlist.remove(u)
					rlist = ','.join(userlist)
					break

		return rlist
class delete(Resource):
	def post(self):
		data = request.get_json()
		# TODO: Implement delete functionality
		uid = b64decode(data['user-id']).decode("utf-8")
		did = b64decode(data['doc-id']).decode("utf-8")
		session_token = b64decode(data['session-token']).decode("utf-8")

		db = TinyDB('db_docs.json')
		documents = Query()
		query_result = db.search(documents.did == did)

		if len(query_result) == 0:
			response = {
				'status': 700,
				'message': 'Other failures',
				'session_token': session_token
			}
		elif str(query_result[0]['uid']) != uid:
			response = {
				'status': 702,
				'message': 'Access denied to delete file',
				'session_token': session_token	
			}
		elif not os.path.exists('documents/' + did):
			response = {
				'status': 704,
				'message': 'Delete failed since file not found on the server',
				'session_token': session_token	
			}
		else:
			if str(query_result[0]['flag']) == '1':
				os.remove('documents/' + did)
				response = {
					'status': 200,
					'message': 'Successfully deleted the file',
					'session_token': session_token
				}
				db.remove(documents.did == did)
			elif str(query_result[0]['flag']) == '2':
				os.remove('documents/' + did)
				if os.path.exists('documents/signed-' + did):
					os.remove('documents/signed-' + did)
				response = {
					'status': 200,
					'message': 'Successfully deleted the file',
					'session_token': session_token
				}
				db.remove(documents.did == did)
		return jsonify(response)
	'''
		Expected response status codes:
		1) 200 - Successfully deleted the file
		2) 702 - Access denied to delete file
		3) 704 - Delete failed since file not found on the server
		4) 700 - Other failures
	'''

class logout(Resource):
	def post(self):
		data = request.get_json()
		# TODO: Implement logout functionality
		uid = b64decode(data['user-id']).decode("utf-8")
		session_token = b64decode(data['session-token']).decode("utf-8")
		response = {
			'status': 200,
			'message': 'Successfully logged out',
			'session_token': session_token
		}
		return jsonify(response)
	'''
		Expected response status codes:
		1) 200 - Successfully logged out
		2) 700 - Failed to log out
	'''

api.add_resource(welcome, '/')
api.add_resource(login, '/login')
api.add_resource(checkin, '/checkin')
api.add_resource(checkout, '/checkout')
api.add_resource(grant, '/grant')
api.add_resource(delete, '/delete')
api.add_resource(logout, '/logout')

def main():
	secure_shared_service.run(debug=True)

if __name__ == '__main__':
	main()
