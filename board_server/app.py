from flask import Flask
from flask import request
from flask import Response
from flask import jsonify
import json
import argparse
import config
import datetime

app = Flask(__name__)
app.config.from_object(config.DevelopmentConfig)
board_file = "board.json"
board = []

@app.route('/', methods=['GET'])
def test():
    return "Test done!\n"

@app.route('/post', methods=['POST'])
def post():
    if not request.is_json:
        return Response(code=400)

    j = request.get_json()
    print(j.keys())
    if "server_timestamp" in j.keys():
        return Response("server_timestamp exists\n", status=400)
    j['server_timestamp'] = datetime.datetime.now().timestamp()
    board.append(j)

    with open(board_file, 'w') as f:
        json.dump(board, f)

    return Response("Success\n", status=200)
    

@app.route('/fetch', methods=['GET'])
def fetch():
    return jsonify(board)

if __name__ == '__main__':
    parser = argparse.ArgumentParser(description='Flask')
    parser.add_argument('--port', default=5000,
                    help='Port to run on')

    args = parser.parse_args()

    app.run(host='0.0.0.0', port=args.port)