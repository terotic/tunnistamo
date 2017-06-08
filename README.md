Install postresql server
```
apt install postgresql
```

Create a postgres user and db as root:
```
createuser <your username>
createdb -O <your username> tunnistamo
```

Clone the repo

```
git clone git@github.com:City-of-Helsinki/tunnistamo.git
cd tunnistamo
```

Initiate a virtualenv
```
pyenv virtualenv tunnistamo-env
pyenv local tunnistamo-env
```

Install the Python requirements
```
pip install prequ
rm requirements.txt
prequ update
pip install -r requirements.txt (don't use `prequ sync`)
```

Create local_settings.py in the repo base dir with
```
DEBUG = True
```

Run migrations:
```
python manage.py migrate
```

Create admin user:
```
python manage.py createsuperuser
```

Run dev server:
```
python manage.py runserver
```
