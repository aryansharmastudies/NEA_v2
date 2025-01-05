from main import session, User
users = session.query(User).all()
for user in users:
    print(f"User id: {user.user_id}, name: {user.name}, email: {user.email}")