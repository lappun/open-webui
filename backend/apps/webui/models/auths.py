from pydantic import BaseModel
from typing import List, Union, Optional
import time
import uuid
import logging
import os
import json
from peewee import *

from apps.webui.models.users import UserModel, Users
from utils.utils import verify_password, get_password_hash, convert_svg_to_base64_and_resize

from apps.webui.internal.db import DB

from config import SRC_LOG_LEVELS

log = logging.getLogger(__name__)
log.setLevel(SRC_LOG_LEVELS["MODELS"])

####################
# DB MODEL
####################


class Auth(Model):
    id = CharField(unique=True)
    email = CharField()
    password = TextField()
    active = BooleanField()

    class Meta:
        database = DB


class AuthModel(BaseModel):
    id: str
    email: str
    password: str
    active: bool = True


####################
# Forms
####################


class Token(BaseModel):
    token: str
    token_type: str


class ApiKey(BaseModel):
    api_key: Optional[str] = None


class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    role: str
    profile_image_url: str


class SigninResponse(Token, UserResponse):
    pass


class SigninForm(BaseModel):
    email: str
    password: str


class ProfileImageUrlForm(BaseModel):
    profile_image_url: str


class UpdateProfileForm(BaseModel):
    profile_image_url: str
    name: str


class UpdatePasswordForm(BaseModel):
    password: str
    new_password: str


class SignupForm(BaseModel):
    name: str
    email: str
    password: str
    profile_image_url: Optional[str] = "/user.png"


class AddUserForm(SignupForm):
    role: Optional[str] = "pending"


class AuthsTable:
    def __init__(self, db):
        self.db = db
        self.db.create_tables([Auth])
        self.create_users_from_json_file()

    def create_users_from_json_file(self):
        json_file_path = os.environ.get('USER_ACCOUNTS_JSON_PATH')

        if json_file_path and os.path.isfile(json_file_path):
            with open(json_file_path, 'r') as file:
                user_accounts = json.load(file)

            for user_account in user_accounts:
                email = user_account.get('email')
                password = get_password_hash(user_account.get('password'))
                name = user_account.get('name')
                default_image_url = convert_svg_to_base64_and_resize(f"https://api.dicebear.com/8.x/initials/svg?seed={name}")
                profile_image_url = user_account.get('profile_image_url', default_image_url)
                role = user_account.get('role', 'pending')

                existing_user = self.get_user_by_email(email)
                if existing_user is None:
                    self.insert_new_auth(email, password, name, profile_image_url, role)
        else:
            log.error("User accounts JSON file not found or not specified")

    def get_user_by_email(self, email):
        return Auth.get_or_none(Auth.email == email)
    
    def insert_new_auth(
        self,
        email: str,
        password: str,
        name: str,
        profile_image_url: str = "/user.png",
        role: str = "pending",
    ) -> Optional[UserModel]:
        log.info("insert_new_auth")

        id = str(uuid.uuid4())

        auth = AuthModel(
            **{"id": id, "email": email, "password": password, "active": True}
        )
        result = Auth.create(**auth.model_dump())

        user = Users.insert_new_user(id, name, email, profile_image_url, role)

        if result and user:
            return user
        else:
            return None

    def authenticate_user(self, email: str, password: str) -> Optional[UserModel]:
        log.info(f"authenticate_user: {email}")
        try:
            auth = Auth.get(Auth.email == email, Auth.active == True)
            if auth:
                if verify_password(password, auth.password):
                    user = Users.get_user_by_id(auth.id)
                    return user
                else:
                    return None
            else:
                return None
        except:
            return None

    def authenticate_user_by_api_key(self, api_key: str) -> Optional[UserModel]:
        log.info(f"authenticate_user_by_api_key: {api_key}")
        # if no api_key, return None
        if not api_key:
            return None

        try:
            user = Users.get_user_by_api_key(api_key)
            return user if user else None
        except:
            return False

    def authenticate_user_by_trusted_header(self, email: str) -> Optional[UserModel]:
        log.info(f"authenticate_user_by_trusted_header: {email}")
        try:
            auth = Auth.get(Auth.email == email, Auth.active == True)
            if auth:
                user = Users.get_user_by_id(auth.id)
                return user
        except:
            return None

    def update_user_password_by_id(self, id: str, new_password: str) -> bool:
        try:
            query = Auth.update(password=new_password).where(Auth.id == id)
            result = query.execute()

            return True if result == 1 else False
        except:
            return False

    def update_email_by_id(self, id: str, email: str) -> bool:
        try:
            query = Auth.update(email=email).where(Auth.id == id)
            result = query.execute()

            return True if result == 1 else False
        except:
            return False

    def delete_auth_by_id(self, id: str) -> bool:
        try:
            # Delete User
            result = Users.delete_user_by_id(id)

            if result:
                # Delete Auth
                query = Auth.delete().where(Auth.id == id)
                query.execute()  # Remove the rows, return number of rows removed.

                return True
            else:
                return False
        except:
            return False


Auths = AuthsTable(DB)
