from django.shortcuts import render
from django.views import View
from django.http import JsonResponse, HttpResponse
from django.contrib.auth import authenticate
from django.contrib.auth.models import User
from .models import generate_profile_token, Checklist, Chore, Token, Record, Profile

from datetime import datetime

import uuid


def authenticate_with_token(token: uuid.UUID or str) -> Profile or None:
    try:
        token = Token.objects.get(token=token)
    except Token.DoesNotExist as e:
        print(f"Incorrect token {token}: {e}")
        return None

    return token.profile


def authenticate_request(request) -> Profile or None:
    if 'token' not in request.headers:
        print('No token found in the request.')
        return None

    return authenticate_with_token(request.headers['token'])


# Create your views here.
class ChoresView(View):
    def get(self, request):
        return render(request, 'chores.html')


class RegisterAPI(View):
    """
    Register using username, email and password.
    """
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

        new_user = User.objects.create_user(
            username=request.POST['username'],
            password=request.POST['password'],
            email=request.POST['email']
        )
        Profile.objects.create(authentication='password', user=new_user)
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

        try:
            profile = Profile.objects.get(user=user)
        except Profile.DoesNotExist:
            return JsonResponse({'error': 'wrong credentials'}, status=401)
        # generate token
        token = generate_profile_token(profile).token
        return JsonResponse({'username': username, 'name': profile.name, 'access_token': token})


class LogoutAPI(View):
    def post(self, request):
        ...


class ChecklistListAPI(View):
    def get(self, request):
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'error': 'not authenticated'}, status=401)

        lists = {'checklists': [x.as_dict() for x in user.checklists()]}
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

        try:
            checklist = user.checklists().get(id=pk)
        except Checklist.DoesNotExist:
            return JsonResponse({'error': 'checklist not found'}, status=404)

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
        response = checklist.as_dict()

        checklist.delete()
        return JsonResponse(response)


class ChecklistShareAPI(View):
    def post(self, request, pk):
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'error': 'not authenticated'}, status=401)

        if 'profile' not in request.POST.keys():
            return JsonResponse({'error': 'bad request'}, status=400)

        checklist = user.checklist_set.get(id=pk)
        if not checklist.share_with(int(request.POST['profile'])):
            return JsonResponse({'error': 'user not found'}, status=404)
        return JsonResponse(checklist.as_dict())


class ChecklistUnshareAPI(View):
    def post(self, request, pk):
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'error': 'not authenticated'}, status=401)

        if 'profile' not in request.POST.keys():
            return JsonResponse({'error': 'bad request'}, status=400)

        try:
            checklist = user.checklists().get(id=pk)
        except Checklist.DoesNotExist:
            return JsonResponse({'error': 'checklist not found'}, status=404)

        result = checklist.unshare_with(int(request.POST['profile']))
        if not result:
            return JsonResponse({'error': 'user not found'}, status=404)
        return JsonResponse(checklist.as_dict())


class ChoreCreateAPI(View):
    def post(self, request, pk):
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'error': 'not authenticated'}, status=401)

        if 'name' not in request.POST.keys():
            return JsonResponse({'error': 'bad request'}, status=400)

        frequency = 7
        if 'frequency' in request.POST.keys() and request.POST['frequency'] != '':
            try:
                frequency = float(request.POST['frequency'])
            except ValueError as e:
                return JsonResponse({'error': str(e)}, status=400)

        try:
            checklist = user.checklists().get(id=pk)
        except Checklist.DoesNotExist:
            return JsonResponse({'error': 'checklist not found'}, status=404)
        new_chore = checklist.add_chore(request.POST['name'], frequency)
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
        log = chore.log(dtg, note)
        return JsonResponse(log.chore.as_deep_dict())


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

        if not ('name' in request.POST.keys() or 'frequency' in request.POST.keys()):
            return JsonResponse({'error': 'bad request'}, status=400)

        if 'name' in request.POST.keys():
            chore.name = request.POST['name']
        if 'list' in request.POST.keys():
            new_list = Checklist.objects.get(owner=user, id=int(request.POST['list']))
            chore.list = new_list
        if 'frequency' in request.POST.keys():
            try:
                frequency = float(request.POST['frequency'])
            except ValueError as e:
                return JsonResponse({'error': e}, status=400)
            chore.frequency = frequency
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
        return JsonResponse(log.chore.as_deep_dict())


class LogDeleteAPI(View):
    def get(self, request, pk):
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'error': 'not authenticated'}, status=401)

        log = Record.objects.get(id=pk, chore__list__owner=user)
        if log is None:
            return JsonResponse({'error': 'not found'}, status=404)

        log.delete()
        return JsonResponse(log.chore.as_deep_dict())


class UserSearchAPI(View):
    def get(self, request):
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'error': 'not authenticated'}, status=401)

        if 'query' not in request.GET.keys():
            return JsonResponse({'error': 'bad_request'}, status=400)

        if request.GET['query'] == "":
            return JsonResponse({'total': 0, 'profiles': []})

        profiles = Profile.objects.filter(user__email__contains=request.GET['query'])
        return JsonResponse({'total': len(profiles),
                             'profiles': [x.as_dict() for x in profiles]})


class UserInfoAPI(View):
    def get(self, request, pk):
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'error': 'not authenticated'}, status=401)

        profile = Profile.objects.get(id=pk)
        return JsonResponse(profile.as_dict())


class UserInfoMeAPI(View):
    def get(self, request):
        user = authenticate_request(request)
        if user is None:
            return JsonResponse({'error': 'not authenticated'}, status=401)

        return JsonResponse(user.as_dict())
