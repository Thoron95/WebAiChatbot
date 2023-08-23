# A web app chatbot using OpenAi chat gpt4.

To get started:
1. You need Python ver 3.10.6 or newer.

2. Copy your openai API Key to 'openaiapikey.txt'

3. Open 'config.cfg' file using text editor, uncomment section relevant to your system and paste the absolute path to users_db/users.db

4. Install required modules, which are listed in 'requirements.txt' file. You can run `pip install -r requirements.txt` to do it in easy way.

5. Start the application using `flask run`.

6. While running the application for the first time, enter 'localhost:5000/init' to create the database and Admin account.
