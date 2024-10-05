from django.shortcuts import render
from django.http import HttpResponseRedirect
from django.shortcuts import render, reverse
from .models import Task
from django.db import connection
from django.core.exceptions import ValidationError


# View functions
def index(request):
	# checks whether user is authenticated
	if request.user.is_authenticated:
		# gets all tasks from the database
		task_list = Task.objects.filter(user=request.user) 
		# creates a dictionary to pass this list to the template file
		template_data = {'tasks': task_list}
		# renders the web page
		return render(request, 'index.html', template_data)
	else:
		return HttpResponseRedirect(reverse(f'login'))

# Adds a new task and redirect it back to index page
def add(request):
	if request.user.is_authenticated:
		# if the form was submitted
		if request.POST:
			title = request.POST['title']
			due_date = request.POST['due_date']
			status = request.POST['status']
			task = Task(user = request.user, title = title, due_date = due_date, status = status)
			# does input validation (full_clean() throws an exception if validation fails)
			try:
				task.full_clean() 
				# if no exception was thrown, form was validated
				# we proceed to save the task in the database
				with connection.cursor() as cursor:
					cursor.executescript(f"INSERT INTO tasktracker_task(user_id, status, due_date, title) VALUES ({request.user.id},'{status}', '{due_date}', '{title}')")				
			except ValidationError as e:
				# renders the web page again with an error message
				return render(request, 'add.html', {"errors": e.message_dict})
				
			return HttpResponseRedirect(reverse(f'tasktracker:index'))
		else:
			# renders the web page
			return render(request, 'add.html')
	else:
		return HttpResponseRedirect(reverse(f'login'))


# Deletes a task (based on its primary key) and redirect it back to index page
def delete(request, pk):
	# uses ORM to delete the task
	task = Task.objects.get(id = pk)
	task.delete()
	# redirects user to index page
	return HttpResponseRedirect(reverse(f'tasktracker:index'))