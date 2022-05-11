from flask import Flask, render_template
import oauth
import login
import boats

app = Flask(__name__)
app.register_blueprint(login.bp)
app.register_blueprint(oauth.bp)
app.register_blueprint(boats.bp)


@app.route('/')
def root():

    return render_template(
        'index.html')


if __name__ == '__main__':
    app.run(host='127.0.0.1', port=8080, debug=True)