


new_pass = sha256_crypt.hash(str(new_pass))
                users_cursor.users.update_many(
                        {"username": session['username']},
                        {'$set': {'password': new_pass}}
                        )