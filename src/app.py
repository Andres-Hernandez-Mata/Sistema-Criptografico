from flask import Flask, render_template

app = Flask(__name__)

@app.route("/")
def main():    
    return render_template("sign_in.html")

@app.route("/sign_up")
def sign_up():    
    return render_template("sign_up.html")

if __name__ == "__main__":
    app.config['TEMPLATES_AUTO_RELOAD'] = True
    app.run(debug = True)


