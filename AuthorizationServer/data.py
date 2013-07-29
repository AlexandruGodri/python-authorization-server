from django.http import HttpResponse
from rest_framework.views import View
from rest_framework.response import Response
from rest_framework import status

import json

import app

class Test(View):
	def get(self, request, clientId, clientSecret, resource, permission):
		try:
			token_data = app.getToken(clientId, clientSecret)
			if token_data == "INVALID_CREDENTIALS":
				return HttpResponse(json.dumps({"error": token_data}), content_type = "application/json", status = 400)
			else:
				token = token_data["token"]
				ret = ""
				for i in range(100):
					value = app.authorize(clientId, token, "user_" + str(i), resource, permission)
					if not value:
						ret = ret + "User " + str(i) + " is not allowed to access resource1 with permission create\n"
					else:
						ret = ret + "User " + str(i) + " is allowed to access " + resource + " with permission " + permission + "\n"
				return HttpResponse(ret, content_type = "text/plain", status = 200)
		except Exception as inst:
			print inst
			return HttpResponse(json.dumps({"error": "INTERNAL_ERROR"}), content_type = "application/json", status = 400)

class RestToken(View):
	def get(self, request, clientId, clientSecret):
		try:
			token_data = app.getToken(clientId, clientSecret)
			if token_data == "INVALID_CREDENTIALS":
				return HttpResponse(json.dumps({"error": token_data}), content_type = "application/json", status = 400)
			else:
				return HttpResponse(json.dumps(token_data), content_type = "application/json", status = 200)
		except Exception as inst:
			print inst
			return HttpResponse(json.dumps({"error": "INTERNAL_ERROR"}), content_type = "application/json", status = 400)

class RestAuthorize(View):
	def get(self, request, clientId, token, user, resource, permission):
		try:
			value = app.authorize(clientId, token, user, resource, permission)
			if not value:
				return HttpResponse(json.dumps({"authorized": False}), content_type = "application/json", status = 400)
			else:
				return HttpResponse(json.dumps({"authorized": True}), content_type = "application/json", status = 200)
		except Exception as inst:
			return HttpResponse(json.dumps({"error": "INTERNAL_ERROR"}), content_type = "application/json", status = 400)

class RestResource(View):
	def put(self, request, clientId, token):
		try:
			resource = request.PUT.get("resource")
			value = app.addResource(clientId, token, resource)
			if value == "INVALID_TOKEN":
				return HttpResponse(json.dumps({"error": "INVALID_TOKEN"}), content_type = "application/json", status = 400)
			else:
				return HttpResponse(json.dumps({"id": value}), content_type = "application/json", status = 200)
		except Exception as inst:
			return HttpResponse(json.dumps({"error": "INTERNAL_ERROR"}), content_type = "application/json", status = 400)

	def delete(self, request, clientId, token):
		try:
			resource = request.DELETE.get("resource")
			value = app.deleteResource(clientId, token, resource)
			if value == "INVALID_TOKEN":
				return HttpResponse(json.dumps({"error": "INVALID_TOKEN"}), content_type = "application/json", status = 400)
			else:
				return HttpResponse(json.dumps({"success": True}), content_type = "application/json", status = 200)
		except Exception as inst:
			return HttpResponse(json.dumps({"error": "INTERNAL_ERROR"}), content_type = "application/json", status = 400)

class RestPermission(View):
	def put(self, request, clientId, token):
		try:
			permission = request.PUT.get("permission")
			value = app.addPermission(clientId, token, permission)
			if value == "INVALID_TOKEN":
				return HttpResponse(json.dumps({"error": "INVALID_TOKEN"}), content_type = "application/json", status = 400)
			else:
				return HttpResponse(json.dumps({"id": value}), content_type = "application/json", status = 200)
		except Exception as inst:
			return HttpResponse(json.dumps({"error": "INTERNAL_ERROR"}), content_type = "application/json", status = 400)

	def delete(self, request, clientId, token):
		try:
			permission = request.DELETE.get("permission")
			value = app.deletePermission(clientId, token, permission)
			if value == "INVALID_TOKEN":
				return HttpResponse(json.dumps({"error": "INVALID_TOKEN"}), content_type = "application/json", status = 400)
			else:
				return HttpResponse(json.dumps({"success": True}), content_type = "application/json", status = 200)
		except Exception as inst:
			return HttpResponse(json.dumps({"error": "INTERNAL_ERROR"}), content_type = "application/json", status = 400)

class RestRole(View):
	def put(self, request, clientId, token):
		try:
			role = request.PUT.get("role")
			resource = request.PUT.get("resource")
			permissions = request.PUT.get("permissions")
			inherits = request.PUT.get("inherits")

			app.createRole(clientId, token, role)
			if resource != None and permissions != None:
				value1 = app.updateRole(clientId, token, role, resource, permissions)
			if inherits != None:
				value2 = app.inheritRole(clientId, token, role, inherits)

			if value1 == "INVALID_TOKEN":
				return HttpResponse(json.dumps({"error": "INVALID_TOKEN"}), content_type = "application/json", status = 400)
			else:
				return HttpResponse(json.dumps({"success": True}), content_type = "application/json", status = 200)
		except Exception as inst:
			return HttpResponse(json.dumps({"error": "INTERNAL_ERROR"}), content_type = "application/json", status = 400)

	def delete(self, request, clientId, token):
		try:
			role = request.DELETE.get("role")
			value = app.deleteRole(clientId, token, role)
			if value == "INVALID_TOKEN":
				return HttpResponse(json.dumps({"error": "INVALID_TOKEN"}), content_type = "application/json", status = 400)
			else:
				return HttpResponse(json.dumps({"success": True}), content_type = "application/json", status = 200)
		except Exception as inst:
			return HttpResponse(json.dumps({"error": "INTERNAL_ERROR"}), content_type = "application/json", status = 400)

class RestUserRole(View):
	def put(self, request, clientId, token):
		try:
			user = request.PUT.get("user")
			role = request.PUT.get("role")
			value = app.updateUserRole(clientId, token, user, role)
			if value == "INVALID_TOKEN":
				return HttpResponse(json.dumps({"error": "INVALID_TOKEN"}), content_type = "application/json", status = 400)
			else:
				return HttpResponse(json.dumps({"success": True}), content_type = "application/json", status = 200)
		except Exception as inst:
			return HttpResponse(json.dumps({"error": "INTERNAL_ERROR"}), content_type = "application/json", status = 400)
	