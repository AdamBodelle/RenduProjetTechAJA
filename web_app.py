import struct

from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)


class Packet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(64), index=True)
    protocol = db.Column(db.String(64), index=True)
    src_bytes = db.Column(db.String(64), index=True)
    flag = db.Column(db.String(64), index=True)
    dst_bytes = db.Column(db.String(64), index=True)

with app.app_context():
    db.drop_all()
    db.create_all()

import pickle
import pandas as pd

model_pkl_file = "./ressource/random_forest_classifier_model.pkl"

with open(model_pkl_file, 'rb') as file:
    model = pickle.load(file)

test = pd.read_csv('./ressource/KDDTest2+.csv')
test = test.drop(['class'], axis=1)


@app.route('/')
def index():
    packets = Packet.query
    return render_template('cybershield.html', title='Cyber shield',
                           packets=packets)


if __name__ == '__main__':
    app.run(debug=True)
