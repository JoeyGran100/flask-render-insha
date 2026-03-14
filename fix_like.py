from app import app, db

with app.app_context():
    db.session.rollback()

    # Force the alembic version to the last known good migration
    db.session.execute(db.text("UPDATE alembic_version SET version_num = '2ec24cfd6bd6'"))
    db.session.commit()
    print("Alembic version stamped to 2ec24cfd6bd6")

    # Re-apply the like table fix
    db.session.execute(db.text('ALTER TABLE "like" DROP CONSTRAINT IF EXISTS pk_like'))
    db.session.execute(db.text('ALTER TABLE "like" DROP CONSTRAINT IF EXISTS like_pkey'))
    db.session.execute(db.text('ALTER TABLE "like" DROP CONSTRAINT IF EXISTS uq_user_post_like'))
    db.session.execute(db.text('ALTER TABLE "like" DROP CONSTRAINT IF EXISTS uq_user_comment_like'))
    db.session.execute(db.text('ALTER TABLE "like" DROP CONSTRAINT IF EXISTS like_on_post_or_comment'))
    db.session.commit()

    db.session.execute(db.text('ALTER TABLE "like" ADD COLUMN IF NOT EXISTS id SERIAL'))
    db.session.commit()

    db.session.execute(db.text('ALTER TABLE "like" ADD CONSTRAINT like_pkey PRIMARY KEY (id)'))
    db.session.commit()

    db.session.execute(db.text('ALTER TABLE "like" ADD CONSTRAINT uq_user_post_like UNIQUE (user_id, post_id)'))
    db.session.execute(db.text('ALTER TABLE "like" ADD CONSTRAINT uq_user_comment_like UNIQUE (user_id, comment_id)'))
    db.session.execute(db.text(
        'ALTER TABLE "like" ADD CONSTRAINT like_on_post_or_comment CHECK ('
        '(post_id IS NOT NULL AND comment_id IS NULL) OR '
        '(post_id IS NULL AND comment_id IS NOT NULL))'
    ))
    db.session.commit()

    print("Done — like table fixed and alembic version corrected")
