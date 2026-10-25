from flask import Flask, request, jsonify
from flask_cors import CORS
import joblib

app = Flask(__name__)
CORS(app)

# Load trained ML model
model = joblib.load("spam_model.pkl")

@app.route("/predict", methods=["POST"])
def predict():
    data = request.get_json()

    message = data.get("message", "")

    if not message.strip():
        return jsonify({"error": "Message is empty"}), 400

    prediction = model.predict([message])[0]
    probability = model.predict_proba([message])[0][1]

    result = "spam" if prediction == 1 else "ham"

    return jsonify({
        "prediction": result,
        "spam_probability": round(float(probability) * 100, 2)
    })


@app.route("/")
def home():
    return "SHIELD 2.0 ML API is running!"


if __name__ == "__main__":
    app.run(debug=True, port=5000)