# =====================================
FROM python:3.6-slim as staticbuilder
# -------------------------------------
# Stage for building static files for
# the project. Installs Node as that
# is required for compiling SCSS files.
# =====================================

# Install node as that is
ENV NODE_VERSION 10.16.3

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      libxmlsec1-dev \
      libxml2-dev \
      pkg-config \
      git \
      curl \
      build-essential

# Use bash instead of sh
RUN rm /bin/sh && ln -s /bin/bash /bin/sh
RUN curl --silent -o- https://raw.githubusercontent.com/nvm-sh/nvm/v0.34.0/install.sh | bash \
    && source ~/.nvm/nvm.sh

ENV PATH="/root/.nvm/versions/node/v$NODE_VERSION/bin:${PATH}"

WORKDIR /app

COPY requirements.txt /app/requirements.txt
COPY package.json /app/package.json
COPY package-lock.json /app/package-lock.json
RUN pip install -U pip \
    && pip install --no-cache-dir  -r /app/requirements.txt
RUN npm install

COPY . /app/
RUN python manage.py collectstatic --noinput \
    && python manage.py compilescss

# ==============================
FROM python:3.6-slim as appbase
# ==============================

ENV PYTHONUNBUFFERED 1

WORKDIR /app

COPY requirements.txt /app/requirements.txt
COPY requirements-prod.txt /app/requirements-prod.txt

# Install main project dependencies and clean up
# Note that production dependencies are installed here as well since
# that is the default state of the image and development stages are
# just extras.
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
      libxmlsec1-dev \
      libxml2-dev \
      netcat \
      pkg-config \
      gettext \
      git \
      build-essential \
    && pip install -U pip \
    && pip install --no-cache-dir  -r /app/requirements.txt \
    && pip install --no-cache-dir  -r /app/requirements-prod.txt \
    && apt-get remove -y build-essential pkg-config git \
    && apt-get purge -y --auto-remove -o APT::AutoRemove::RecommendsImportant=false \
    && rm -rf /var/lib/apt/lists/* \
    && rm -rf /var/cache/apt/archives

COPY docker-entrypoint.sh /app
ENTRYPOINT ["./docker-entrypoint.sh"]

# STore static files under /var to not conflict with development volume mount
ENV STATIC_ROOT /var/tunnistamo/static
ENV NODE_MODULES_ROOT /var/tunnistamo/node_modules
# Copy over static files with owner nobody as this is what uWSGI will run as
COPY --from=staticbuilder --chown=nobody:nogroup /app/static /var/tunnistamo/static
COPY --from=staticbuilder --chown=nobody:nogroup /app/node_modules /var/tunnistamo/node_modules

# =========================
FROM appbase as development
# =========================

COPY requirements-dev.txt /app/requirements-dev.txt
RUN pip install --no-cache-dir  -r /app/requirements-dev.txt \
  && pip install --no-cache-dir prequ

ENV DEV_SERVER=1

COPY . /app/

EXPOSE 8000/tcp

# ==========================
FROM appbase as production
# ==========================

COPY . /app/

EXPOSE 8000/tcp
