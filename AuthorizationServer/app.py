import hashlib
import datetime
import time
from pymongo import MongoClient

def _showCollection(coll):
	col = _getCollection(coll)
	for i in col.find():
		print i

def _encodeSecret(secret):
	return hashlib.md5(secret + "SOME_UNIQUE_SECRET").hexdigest()
	
def _getCollection(collectionName):
	client = MongoClient('localhost', 27017)
	db = client['rbac']
	collection = db[collectionName]
	return collection
 
def _generateToken(clientId):
	return hashlib.md5(clientId + "TOKEN_UNIQUE_SECRET" + str(time.time())).hexdigest()

def _checkToken(clientId, token):
	oauth = _getCollection("oauth")
	doc = oauth.find_one({"client": clientId, "token": token})
	
	if doc == None:
		return False
	
	if doc["expire"] < time.time():
		return False

	return True
	
def addClient(clientId, clientSecret):
	clients = _getCollection("clients")
	clients.update({'client': clientId}, {"$set": {"client": clientId, "secret": _encodeSecret(clientSecret)}}, upsert = True)

def getToken(clientId, clientSecret):
	encodedSecret = _encodeSecret(clientSecret)
	clients = _getCollection("clients")
	oauth = _getCollection("oauth")

	client = clients.find_one({"client": clientId, "secret": encodedSecret})
	if client == None:
		return "INVALID_CREDENTIALS"
	
	_token = _generateToken(clientId)
	_expire = time.time() + 3600

	data = {
		"client": clientId,
		"token": _token,
		"expire": _expire
	}

	doc = oauth.find_one({"client": clientId})
	if doc == None:
		token_id = oauth.insert(data)
		return data
	
	if doc["expire"] < time.time():
		oauth.update({"client": clientId}, {"$set": {"token": _token, "expire": _expire}})
		return data

	data["token"] = doc["token"]
	data["expire"] = doc["expire"]
	return data

def _addValue(clientId, token, category, value):
	if not _checkToken(clientId, token):
		return "INVALID_TOKEN"
	
	col = _getCollection(category)
	
	doc = col.find_one({"client": clientId, "value": value})
	if doc == None:
		data = {
			"client": clientId,
			"value": value
		}
		value_id = col.insert(data)
		return value_id
	 
	return doc["_id"]
	 
def _deleteValue(clientId, token, category, value):
	if not _checkToken(clientId, token):
		return "INVALID_TOKEN"

	col = _getCollection(category)
	col.remove({"client": clientId, "value": value})

def addResource(clientId, token, value):
	return _addValue(clientId, token, "resources", value)

def deleteResource(clientId, token, value):
	_deleteValue(clientId, token, "resources", value)

def addPermission(clientId, token, value):
	return _addValue(clientId, token, "permissions", value)

def deletePermission(clientId, token, value):
	_deleteValue(clientId, token, "permissions", value)

def createRole(clientId, token, role):
	if not _checkToken(clientId, token):
		return "INVALID_TOKEN"
	col = _getCollection("roles")
	col.update({"client": clientId, "role": role}, {"$set": {"client": clientId, "role": role}}, upsert = True)

def inheritRole(clientId, token, role, inheritsFrom):
	if not _checkToken(clientId, token):
		return "INVALID_TOKEN"
	col = _getCollection("roles")
	col.update({"client": clientId, "role": role}, {"$set": {"client": clientId, "role": role, "inheritsFrom": inheritsFrom}}, upsert = True)

def updateRole(clientId, token, role, resource, permissions):
	if not _checkToken(clientId, token):
		return "INVALID_TOKEN"
	col = _getCollection("roles")
	col.update({"client": clientId, "role": role}, {"$set": {"client": clientId, "role": role, "resources." + resource: permissions}}, upsert = True)

def deleteRole(clientId, token, role):
	if not _checkToken(clientId, token):
		return "INVALID_TOKEN"

	col = _getCollection("roles")
	col.remove({"client": clientId, "role": role})

def updateUserRole(clientId, token, user, role):
	if not _checkToken(clientId, token):
		return "INVALID_TOKEN"
	col = _getCollection("user_roles")
	col.update({"client": clientId, "user": user}, {"$set": {"client": clientId, "role": role, "user": user}}, upsert = True)

def authorize(clientId, token, user, resource, permission):
	if not _checkToken(clientId, token):
		return False

	user_roles = _getCollection("user_roles")
	roles = _getCollection("roles")
	resources = _getCollection("resources")
	permissions = _getCollection("permissions")

	doc1 = user_roles.find_one({"client": clientId, "user": user})
	doc2 = roles.find_one({"client": clientId, "role": doc1["role"]})

	for i in doc2["resources"]:
		if i == resource and permission in doc2["resources"][i]:
			return True

	if "inheritsFrom" in doc2:
		doc3 = roles.find_one({"client": clientId, "role": doc2["inheritsFrom"]})
		if doc3 != None:
			for i in doc3["resources"]:
				if i == resource and permission in doc3["resources"][i]:
					return True

	return False
