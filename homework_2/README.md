# Homework 2

This project consists of a basic Django-based web-site to track user tasks.
The sample software has been provided with some security vulnerabilities, which have been addressed and fixed in this repository.

## Getting Started

Given that it is a Django application, it requires you to have the Django library installed on your node.

It has been tested with Python `3.10.13` and the following list of python libraries:
```
Package           Version
----------------- -------
bleach            6.1.0
Django            5.1.1
```

### Running the program

This method describes how to execute this software from a Python (virtual) environment. It assumes that you have `git` and Python 3 installed in your node.

1. (Optional) If you have `virtualenvwrapper`, you can create a new python virtual environment with (or, use your favorite virtual environment library.):
```
mkvirtualenv alan-hw2
```
2. Clone this repository with:
```
git clone https://github.com/amaltaro/cse-60770.git
```
3. Access the project directory:
```
cd cse-60770/homework_2/
```
4. Install the Python dependencies:
```
pip3 install -r requirements.txt
```
5. Finally, run the Django application with:
```
python website/manage.py runserver
```

Now a web-service should be running in your localhost node. Go to a web browser and access it through: http://127.0.0.1:8000/tasktracker
