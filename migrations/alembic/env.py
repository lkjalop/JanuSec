from __future__ import annotations
import os
import sys
from logging.config import fileConfig

from sqlalchemy import engine_from_config
from sqlalchemy import pool

from alembic import context

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
fileConfig(config.config_file_name)

# set database URL from env if provided
db_url = os.getenv('APP_DB_DSN') or os.getenv('DATABASE_URL')
if db_url:
    config.set_main_option('sqlalchemy.url', db_url)


def run_migrations_offline():
    url = config.get_main_option('sqlalchemy.url')
    context.configure(url=url, literal_binds=True)
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online():
    configuration = config.get_section(config.config_ini_section) or {}
    url = config.get_main_option('sqlalchemy.url')
    if url:
        configuration['sqlalchemy.url'] = url
    if not configuration.get('sqlalchemy.url'):
        raise RuntimeError('DATABASE_URL_or_APP_DB_DSN_required_for_alembic')
    connectable = engine_from_config(
        configuration,
        prefix='sqlalchemy.',
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(connection=connection)
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
