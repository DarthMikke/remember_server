from django.shortcuts import render
from django.views import View
from django.http import JsonResponse
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from .models import generate_token, Checklist, Chore, Token, Record

from datetime import datetime

import uuid


def authenticate_with_token(token: uuid.UUID or str) -> User or None:
    try:
        token = Token.objects.get(token=token)
    except Token.DoesNotExist as e:
        print(f"Incorrect token {token}: {e}")
        return None

    return token.user


def authenticate_request(request) -> User or None:
    if 'token' not in request.headers:
        print('No token found in the request.')
        return None

    return authenticate_with_token(request.headers['token'])


# Create your views here.
class ChoresView(View):
    def get(self, request):
        return render(request, 'chores.html')


class RegisterAPI(View):
    def post(self, request):
        keys = request.POST.keys()
        if not ('username' in keys and 'password' in keys and 'email' in keys):
            return JsonResponse({'error': 'wrong credentials'}, status=401)

        # Check if user exists already
        try:
            user = User.objects.get(username=request.POST['username'])
            return JsonResponse({'error': 'this user exists already'}, status=401)
        except User.DoesNotExist:
            pass

        User.objects.create_user(
            username=request.POST['username'],
            password=request.POST['password'],
            email=request.POST['email']
        )
        return JsonResponse({'status': 'success'})


class LoginAPI(View):
    def post(self, request):
        keys = request.POST.keys()
        if not ('username' in keys and 'password' in keys):
            return JsonResponse({'error': 'wrong credentials'}, status=401)

        username = request.POST['username']
        password = request.POST['password']
        user = authenticate(request, username=username, password=password)
        if user is None:
            return JsonResponse({'error': 'wrong credentials'}, status=401)

        # generate token
        token = generate_token(user).token
        return JsonResponse({'username': username, 'access_token': token})


class LogoutAPI(View):
    def post(self, request):
        ...


class ChecklistListAPI(View):
    def get(self, request):
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'error': 'not authenticated'}, status=401)

        lists = {'checklists': [x.as_dict() for x in user.checklist_set.all()]}
        return JsonResponse(lists)


class ChecklistCreateAPI(View):
    def post(self, request):
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'error': 'not authenticated'}, status=401)

        if 'name' not in request.POST.keys():
            return JsonResponse({'error': 'bad request'}, status=400)

        new_checklist = Checklist.objects.create(owner=user, name=request.POST['name'])
        return JsonResponse(new_checklist.as_dict())


class ChecklistReadAPI(View):
    def get(self, request, pk):
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'error': 'not authenticated'}, status=401)

        checklist = user.checklist_set.get(id=pk)
        # TODO: 404 if checklist is None
        return JsonResponse(checklist.as_deep_dict())


class ChecklistUpdateAPI(View):
    def post(self, request, pk):
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'error': 'not authenticated'}, status=401)

        if 'name' not in request.POST.keys():
            return JsonResponse({'error': 'bad request'}, status=400)

        checklist = user.checklist_set.get(id=pk)
        checklist.name = request.POST['name']
        checklist.save()
        return JsonResponse(checklist.as_dict())


class ChecklistDeleteAPI(View):
    def get(self, request, pk):
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'error': 'not authenticated'}, status=401)

        checklist = user.checklist_set.get(id=pk)
        # TODO: 404 if checklist is None

        checklist.delete()
        return JsonResponse(checklist.as_dict())


class ChoreCreateAPI(View):
    def post(self, request, pk):
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'error': 'not authenticated'}, status=401)

        if 'name' not in request.POST.keys():
            return JsonResponse({'error': 'bad request'}, status=400)

        checklist = Checklist.objects.get(id=pk)
        new_chore = checklist.add_chore(request.POST['name'])
        return JsonResponse(new_chore.as_dict())


class ChoreLogAPI(View):
    def get(self, request, pk):
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'error': 'not authenticated'}, status=401)

        chore = Chore.objects.get(id=pk, list__owner=user)
        if chore is None:
            return JsonResponse({'error': 'not found'}, status=404)

        dtg = datetime.now()
        if 'date' in request.GET.keys():
            dtg = request.GET['date']
            dtg = dtg.replace('Z', "+00:00")
            dtg = datetime.fromisoformat(dtg)
        note = request.GET['note'] if 'note' in request.GET.keys() else request.GET['note']
        print(f'Logging chore {pk} at {dtg} with note {note}')
        new_record = chore.log(dtg, note)
        return JsonResponse(new_record.as_dict())


class ChoreReadAPI(View):
    def get(self, request, pk):
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'error': 'not authenticated'}, status=401)

        chore = Chore.objects.get(id=pk, list__owner=user)
        if chore is None:
            return JsonResponse({'error': 'not found'}, status=404)

        return JsonResponse(chore.as_deep_dict())


class ChoreUpdateAPI(View):
    def post(self, request, pk):
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'error': 'not authenticated'}, status=401)

        chore = Chore.objects.get(id=pk, list__owner=user)
        if chore is None:
            return JsonResponse({'error': 'not found'}, status=404)

        if not ('name' in request.GET.keys() or 'list' in request.GET.keys()):
            return JsonResponse({'error': 'bad request'}, status=400)

        if 'name' in request.GET.keys():
            chore.name = request.GET['name']
        if 'list' in request.GET.keys():
            new_list = Checklist.objects.get(owner=user, id=int(request.GET['list']))
            chore.list = new_list
        chore.save()

        return JsonResponse(chore.as_dict())


class ChoreDeleteAPI(View):
    def get(self, request, pk):
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'error': 'not authenticated'}, status=401)

        chore = Chore.objects.get(id=pk, list__owner=user)
        if chore is None:
            return JsonResponse({'error': 'not found'}, status=404)
        chore.delete()

        return JsonResponse(chore.as_dict())


class LogUpdateAPI(View):
    def get(self, request, pk):
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'error': 'not authenticated'}, status=401)

        if 'timestamp' not in request.GET.keys():
            return JsonResponse({'error': 'bad request'}, status=400)

        try:
            new_timestamp=datetime.fromisoformat(request.GET['timestamp'])
        except Exception as e:
            return JsonResponse({'error': e}, status=400)

        log = Record.objects.get(id=pk, chore__list__owner=user)
        if log is None:
            return JsonResponse({'error': 'not found'}, status=404)

        log.timestamp = new_timestamp
        log.save()
        return JsonResponse(log.as_dict())


class LogDeleteAPI(View):
    def get(self, request, pk):
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'error': 'not authenticated'}, status=401)

        log = Record.objects.get(id=pk, chore__list__owner=user)
        if log is None:
            return JsonResponse({'error': 'not found'}, status=404)

        log.delete()
        return JsonResponse(log.as_dict())
