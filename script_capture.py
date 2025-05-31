import scapy.all as scapy
from flask import Flask, render_template
from flask_sqlalchemy import SQLAlchemy
import pickle
import pandas as pd

app = Flask(__name__)
app.config['SQLALCHEMY_DATABASE_URI'] = 'sqlite:///db.sqlite'
app.config['SQLALCHEMY_TRACK_MODIFICATIONS'] = False
db = SQLAlchemy(app)

model_pkl_file = "./ressource/random_forest_classifier_model_optimized.pkl"

with open(model_pkl_file, 'rb') as file:
    model = pickle.load(file)

with app.app_context():
    db.create_all()

flags_tab = {'OTH':0, 'REJ':1, 'RSTO':2, 'RSTOS0':3, 'RSTR':4, 'S0':5, 'S1':6, 'S2':7, 'S3':8, 'SF':9, 'SH':10}
protocols_tab = {'ICMP': 0, 'TCP': 1, 'UDP': 2}

class Packet(db.Model):
    id = db.Column(db.Integer, primary_key=True)
    type = db.Column(db.String(64), index=True)
    protocol = db.Column(db.String(64), index=True)
    src_bytes = db.Column(db.String(64), index=True)
    flag = db.Column(db.String(64), index=True)
    dst_bytes = db.Column(db.String(64), index=True)

def print_info(packet):
    print(packet.show())
    if 'TCP' in packet:
        protocol = 'TCP'
        flags = packet['TCP'].flags
        flag = 'OTH'
        if 'S' in flags and 'F' in flags:
            flag = 'SF'
        elif 'S' in flags:
            flag = 'S0'
        elif 'F' in flags:
            flag = 'REJ'
        elif 'R' in flags:
            flag = 'RSTO'
        elif 'R' in flags and 'A' in flags:
            flag = 'RSTR'
        source_bytes = len(packet)
        destination_bytes = len(packet.payload)

        features = pd.DataFrame({
            'protocol_type':[protocols_tab[protocol],],
            'flag':[flags_tab[flag],],
            'src_bytes':[source_bytes,],
            'dst_bytes':[destination_bytes,]
        })

        if model.predict(features):
            ptype = 'Attaque'
        else:
            ptype = 'Ok'
        db.session.add(Packet(type=ptype, protocol=protocol, flag=flag, src_bytes=source_bytes, dst_bytes=destination_bytes))
        db.session.commit()

    if 'UDP' in packet:
        protocol = 'UDP'
        flag = 'SF'
        source_bytes = len(packet)
        destination_bytes = len(packet.payload)

        features = pd.DataFrame({
            'protocol_type': [protocols_tab[protocol], ],
            'flag': [flags_tab[flag], ],
            'src_bytes': [source_bytes, ],
            'dst_bytes': [destination_bytes, ]
        })

        if model.predict(features):
            ptype = 'Attaque'
        else:
            ptype = 'Ok'
        db.session.add(
            Packet(type=ptype, protocol=protocol, flag=flag, src_bytes=source_bytes,
                   dst_bytes=destination_bytes))
        db.session.commit()

    if 'ICMP' in packet:
        protocol = 'ICMP'
        flag = 'SF'
        source_bytes = len(packet)
        destination_bytes = len(packet.payload)

        features = pd.DataFrame({
            'protocol_type': [protocols_tab[protocol], ],
            'flag': [flags_tab[flag], ],
            'src_bytes': [source_bytes, ],
            'dst_bytes': [destination_bytes, ]
        })

        if model.predict(features):
            ptype = 'Attaque'
        else:
            ptype = 'Ok'
        db.session.add(
            Packet(type=ptype, protocol=protocol, flag=flag, src_bytes=source_bytes,
                   dst_bytes=destination_bytes))
        db.session.commit()

if __name__ == '__main__':
    with app.app_context():
        interface_name= 'Wi-Fi'  #Nom à changer en fct du besoin
        p = scapy.sniff(iface=interface_name, prn=print_info) #count optionnel si écoute en continu
