import os
import math
import ssl
import urllib.parse
import datetime
from datetime import timedelta, date
import json 
import requests

from dotenv import load_dotenv
load_dotenv()

from flask import Flask, render_template, redirect, session, request, url_for, flash, jsonify, Blueprint
from werkzeug.security import generate_password_hash, check_password_hash
from flask_wtf.csrf import CSRFProtect
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity

from sqlalchemy.pool import NullPool

from extensions import db, jwt
from models import User, Expense, LoginAttempt
from form import RegistrationForm, LoginForm

__all__ = [
    # Standard Libraries & Utils
    'os', 'math', 'ssl', 'urllib', 'datetime', 'timedelta', 'date', 'load_dotenv', 'NullPool',
    # Flask Core & Extensions
    'Flask', 'render_template', 'redirect', 'session', 'request', 'url_for', 'flash',
    'jsonify', 'Blueprint', 'generate_password_hash', 'check_password_hash',
    'CSRFProtect', 'create_access_token', 'jwt_required', 'get_jwt_identity',
    # Database, Models & Forms
    'db', 'jwt', 'User', 'Expense', 'LoginAttempt', 'RegistrationForm', 'LoginForm'
]
