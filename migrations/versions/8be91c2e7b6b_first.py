"""first

Revision ID: 8be91c2e7b6b
Revises: 
Create Date: 2024-07-15 14:35:16.142227

"""
from alembic import op
import sqlalchemy as sa


# revision identifiers, used by Alembic.
revision = '8be91c2e7b6b'
down_revision = None
branch_labels = None
depends_on = None


def upgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    op.drop_table('_comments_old_20240715')
    op.drop_table('_comments_old_20240715_1')
    with op.batch_alter_table('comments', schema=None) as batch_op:
        batch_op.add_column(sa.Column('rate', sa.Integer(), nullable=True))
        batch_op.add_column(sa.Column('desc', sa.String(), nullable=True))
        batch_op.alter_column('date',
               existing_type=sa.TEXT(),
               type_=sa.String(),
               existing_nullable=True)

    # ### end Alembic commands ###


def downgrade():
    # ### commands auto generated by Alembic - please adjust! ###
    with op.batch_alter_table('comments', schema=None) as batch_op:
        batch_op.alter_column('date',
               existing_type=sa.String(),
               type_=sa.TEXT(),
               existing_nullable=True)
        batch_op.drop_column('desc')
        batch_op.drop_column('rate')

    op.create_table('_comments_old_20240715_1',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('body', sa.TEXT(), nullable=False),
    sa.Column('author_id', sa.INTEGER(), nullable=True),
    sa.Column('post_id', sa.INTEGER(), nullable=True),
    sa.Column('date', sa.DATE(), nullable=True),
    sa.ForeignKeyConstraint(['author_id'], ['users.id'], ),
    sa.ForeignKeyConstraint(['post_id'], ['blog_posts.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('_comments_old_20240715',
    sa.Column('id', sa.INTEGER(), nullable=False),
    sa.Column('body', sa.TEXT(), nullable=False),
    sa.Column('author_id', sa.INTEGER(), nullable=True),
    sa.Column('post_id', sa.INTEGER(), nullable=True),
    sa.ForeignKeyConstraint(['author_id'], ['users.id'], ),
    sa.ForeignKeyConstraint(['post_id'], ['blog_posts.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    # ### end Alembic commands ###