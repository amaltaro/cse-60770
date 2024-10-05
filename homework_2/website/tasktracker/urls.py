from django.urls import path
from . import views

app_name = 'tasktracker'  # creates a namespace for this application


urlpatterns = [
    # ex: /tasktracker/
    path('', views.index, name='index'),
    # ex: /tasktracker/add/
    path('add/', views.add, name='add'),
    # ex: /tasktracker/delete/5
    path('delete/<int:pk>/', views.delete, name='delete'),
]

