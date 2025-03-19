from sqlalchemy import create_engine, text
engine = create_engine("sqlite+pysqlite:///database/database.db", echo=True) # lazy connection
# only connects the first time its asked to perform a task.
with engine.connect() as conn:
    result = conn.execute(text("select 'hello world'"))
    print(result.all())