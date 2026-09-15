"""optional pgvector extension and ANN index

Revision ID: 0004_pgvector_optional
Revises: 0003_factor_embeddings
Create Date: 2026-01-19 00:00:00.000000
"""
from alembic import op
import sqlalchemy as sa

# revision identifiers, used by Alembic.
revision = '0004_pgvector_optional'
down_revision = '0003_factor_embeddings'
branch_labels = None
depends_on = None


def upgrade():
    bind = op.get_bind()
    if getattr(bind.dialect, 'name', '') != 'postgresql':
        return
    # Enable pgvector extension if available
    op.execute("CREATE EXTENSION IF NOT EXISTS vector;")
    # Best-effort: convert embedding column to vector and create ivfflat index
    op.execute(
        """
        DO $$
        BEGIN
            BEGIN
                ALTER TABLE factor_embeddings
                    ALTER COLUMN embedding TYPE vector(384)
                    USING embedding::vector;
            EXCEPTION WHEN undefined_object OR invalid_parameter_value OR datatype_mismatch THEN
                -- If vector type isn't available or data is incompatible, skip conversion.
                NULL;
            END;
        END $$;
        """
    )
    op.execute(
        """
        DO $$
        BEGIN
            BEGIN
                CREATE INDEX IF NOT EXISTS idx_factor_embeddings_embedding_cosine
                    ON factor_embeddings
                    USING ivfflat (embedding vector_cosine_ops) WITH (lists = 100);
            EXCEPTION WHEN undefined_object THEN
                NULL;
            END;
        END $$;
        """
    )


def downgrade():
    bind = op.get_bind()
    if getattr(bind.dialect, 'name', '') != 'postgresql':
        return
    op.execute("DROP INDEX IF EXISTS idx_factor_embeddings_embedding_cosine;")
