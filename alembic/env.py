from __future__ import with_statement

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

# this is the Alembic Config object, which provides
# access to the values within the .ini file in use.
config = context.config

# Interpret the config file for Python logging.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# set sqlalchemy.url from env if present
database_url = os.environ.get('DATABASE_URL') or os.environ.get('APP_DB_DSN')
if database_url:
    config.set_main_option('sqlalchemy.url', database_url)

# No Model metadata here; autogenerate would need SQLAlchemy models.
target_metadata = None


def run_migrations_offline() -> None:
    url = config.get_main_option('sqlalchemy.url')
    context.configure(url=url, target_metadata=target_metadata, literal_binds=True)

    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    section = config.get_section(config.config_ini_section) or {}
    url = config.get_main_option('sqlalchemy.url')
    if url:
        section['sqlalchemy.url'] = url
    if not section.get('sqlalchemy.url'):
        raise RuntimeError('DATABASE_URL_or_APP_DB_DSN_required_for_alembic')
    connectable = engine_from_config(
        section,
        prefix='sqlalchemy.',
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(connection=connection, target_metadata=target_metadata)

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
