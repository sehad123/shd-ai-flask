"""Added email column to User

Revision ID: 9dd510b6c9bc
Revises: 
Create Date: 2024-07-28 12:46:27.610580

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '9dd510b6c9bc'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.add_column(sa.Column('email', sa.String(length=120), nullable=True))
        batch_op.create_unique_constraint('uq_user_email', ['email'])


def downgrade():
    with op.batch_alter_table('user', schema=None) as batch_op:
        batch_op.drop_constraint('uq_user_email', type_='unique')
        batch_op.drop_column('email')

    # ### end Alembic commands ###
