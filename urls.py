from django.urls import path
from .views import *

urlpatterns = [
    path('index.html', ChoresView.as_view(), name='index'),
    path('app.html', ChoresView.as_view(), name='app'),
    path('api/cookie', csrf, name='csrf'),
    # User management
    path('api/register', RegisterAPI.as_view(), name='api_register'),
    path('api/login', LoginAPI.as_view(), name='api_login'),
    # path('api/logout', LogoutAPI.as_view(), name='api_logout'),
    # Checklists
    path('api/checklists/', ChecklistListAPI.as_view(), name='checklist_list'),
    path('api/checklist/add', ChecklistCreateAPI.as_view(), name='checklist_add'),
    path('api/checklist/<pk>/', ChecklistReadAPI.as_view(), name='checklist'),
    path('api/checklist/<pk>/update', ChecklistUpdateAPI.as_view(), name='checklist_update'),
    path('api/checklist/<pk>/delete', ChecklistDeleteAPI.as_view(), name='checklist_delete'),
    path('api/checklist/<pk>/add_chore', ChoreCreateAPI.as_view(), name='chore_add'),
    # Chores
    path('api/chore/<pk>/', ChoreReadAPI.as_view(), name='chore'),
    path('api/chore/<pk>/update', ChoreUpdateAPI.as_view(), name='chore_update'),
    path('api/chore/<pk>/delete', ChoreDeleteAPI.as_view(), name='chore_delete'),
    path('api/chore/<pk>/log', ChoreLogAPI.as_view(), name='chore_log'),
    # Logs
    path('api/log/<pk>/update', LogUpdateAPI.as_view(), name='log_update'),
    path('api/log/<pk>/delete', LogDeleteAPI.as_view(), name='log_delete'),
]
