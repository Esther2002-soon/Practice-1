"""create user table

Revision ID: dd8475a6470f
Revises: 
Create Date: 2023-05-18 10:38:04.444979

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = 'dd8475a6470f'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    op.create_table(
        'usertable',
        sa.Column('username',sa.VARCHAR,primary_key=True)
    )


def downgrade():
    op.drop_table('usertable')