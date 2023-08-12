# Custom-Authentication System

---

# Goal

The purpose of this project is to explore the way an authentication system could be built on the web, while keeping the end users' data safe from potential attackers. Using the Flask Framework , I created the corresponding API routes and some basic templates representing the login/register and dashboard pages. Some of the concepts being used in the project are:

* Cookie based Authentication.
* Creating Database models and storing Users using the SQLAlchemy ORM.
* Encrypting passwords using password hashing algorithms.
* Sessions stored in a Redis Database.
* Rate limiting the clients' requests.

---

# The Stack

1. [Python 3](https://www.python.org/)
2. [Flask](https://flask.palletsprojects.com/en/2.3.x/)
3. [Flask-SQLAlchemy ORM](https://flask-sqlalchemy.palletsprojects.com/en/3.0.x/)
4. [PostgreSQL](https://www.postgresql.org/) Database (storing user related data).
5. [Redis](https://redis.io/) Database (storing session and rate limiting data).

---

# Running the project on your local Environment

*<u>Make sure Postgres and redis are installed, up and running in your system.
Also dont forget to create a database in Postgres.The tables will be automatically be generated by our ORM</u>*

### *Creating the .env file...*

1. Create a .env file in the root of the project
2. Copy the .example_env contents to your .env file
3. Provide the required parameters as mention in the .example_env file

---

### *Creating a .venv and Running the app...*

1. Create a Virtual environment in the root of the project

```bash
      python -m venv /path/to/new/virtual/environment
```

2. Activate the virtual environment depending on your shell and platform.

<table class="docutils align-default">
<colgroup>
<col style="width: 17%">
<col style="width: 16%">
<col style="width: 67%">
</colgroup>
<thead>
<tr class="row-odd"><th class="head"><p>Platform</p></th>
<th class="head"><p>Shell</p></th>
<th class="head"><p>Command to activate virtual environment</p></th>
</tr>
</thead>
<tbody>
<tr class="row-even"><td rowspan="4"><p>POSIX</p></td>
<td><p>bash/zsh</p></td>
<td><p><code class="samp docutils literal notranslate"><span class="pre">$</span> <span class="pre">source</span> <em><span class="pre">&lt;venv&gt;</span></em><span class="pre">/bin/activate</span></code></p></td>
</tr>
<tr class="row-odd"><td><p>fish</p></td>
<td><p><code class="samp docutils literal notranslate"><span class="pre">$</span> <span class="pre">source</span> <em><span class="pre">&lt;venv&gt;</span></em><span class="pre">/bin/activate.fish</span></code></p></td>
</tr>
<tr class="row-even"><td><p>csh/tcsh</p></td>
<td><p><code class="samp docutils literal notranslate"><span class="pre">$</span> <span class="pre">source</span> <em><span class="pre">&lt;venv&gt;</span></em><span class="pre">/bin/activate.csh</span></code></p></td>
</tr>
<tr class="row-odd"><td><p>PowerShell</p></td>
<td><p><code class="samp docutils literal notranslate"><span class="pre">$</span> <em><span class="pre">&lt;venv&gt;</span></em><span class="pre">/bin/Activate.ps1</span></code></p></td>
</tr>
<tr class="row-even"><td rowspan="2"><p>Windows</p></td>
<td><p>cmd.exe</p></td>
<td><p><code class="samp docutils literal notranslate"><span class="pre">C:\&gt;</span> <em><span class="pre">&lt;venv&gt;</span></em><span class="pre">\Scripts\activate.bat</span></code></p></td>
</tr>
<tr class="row-odd"><td><p>PowerShell</p></td>
<td><p><code class="samp docutils literal notranslate"><span class="pre">PS</span> <span class="pre">C:\&gt;</span> <em><span class="pre">&lt;venv&gt;</span></em><span class="pre">\Scripts\Activate.ps1</span></code></p></td>
</tr>
</tbody>
</table>
3. install the required dependencies in your virtual environment (located in requirements.txt)
```bash
  pip install -r requirements.txt
```
4. Run the __init__.py file located in the root folder of the project.
```bash
  python __init__.py
```