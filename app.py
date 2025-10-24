# app.py
from flask import Flask, request, jsonify
from flask_cors import CORS
import re
import urllib.parse
import joblib
import tldextract
import logging
import os

app = Flask(__name__, static_folder="static", static_url_path="/")
CORS(app)
logging.basicConfig(level=logging.INFO)
logger = logging.getLogger("phishing_api")

# ----- Feature extraction (unchanged) -----
def clean_url(url: str) -> str:
    return url.replace("[.]", ".")

def extract_features_from_url(url: str):
    url = clean_url(url)
    features = []

    if not re.match(r"^https?://", url, flags=re.IGNORECASE):
        url = "http://" + url

    try:
        parsed = urllib.parse.urlparse(url)
        hostname = parsed.hostname or ""
        query = parsed.query or ""
        try:
            port = parsed.port
        except ValueError:
            port = None
    except Exception as e:
        logger.exception("URL parsing failed")
        return [1] * 11

    ip_pattern = r"^\d{1,3}(\.\d{1,3}){3}(:\d+)?$"
    features.append(1 if re.match(ip_pattern, hostname) else -1)

    length = len(url)
    if length < 54:
        features.append(-1)
    elif length <= 75:
        features.append(0)
    else:
        features.append(1)

    shorteners = [
        "bit.ly", "goo.gl", "tinyurl.com", "ow.ly", "t.co", "bit.do",
        "mcaf.ee", "su.pr", "is.gd", "buff.ly", "tiny.cc", "lnkd.in",
        "shorturl.at", "cutt.ly", "rb.gy", "v.gd", "tiny.one"
    ]
    features.append(1 if any(s in url for s in shorteners) else -1)

    features.append(1 if "@" in url else -1)

    after_protocol = re.sub(r"^https?://", "", url, flags=re.IGNORECASE)
    features.append(1 if after_protocol.count("//") > 1 else -1)

    features.append(1 if "-" in (urllib.parse.urlparse(url).hostname or "") else -1)

    ext = tldextract.extract(url)
    subdomain_count = len(ext.subdomain.split(".")) if ext.subdomain else 0
    if subdomain_count <= 1:
        features.append(-1)
    elif subdomain_count == 2:
        features.append(0)
    else:
        features.append(1)

    features.append(1 if urllib.parse.urlparse(url).scheme.lower() == "https" else -1)
    try:
        port = urllib.parse.urlparse(url).port
    except Exception:
        port = None
    features.append(1 if (port and port not in [80, 443]) else -1)
    features.append(1 if query != "" else -1)
    google_hosted = 1 if ("sites.google.com" in url or "drive.google.com" in url) else -1
    features.append(google_hosted)

    return features

# ----- Reasoning helper -----
def reasons_from_features(features, url):
    """
    Turn the numeric feature vector into human-friendly reasons.
    Returns a list of strings (may be empty if nothing suspicious).
    """
    reasons = []
    # Ensure features length 11
    if not isinstance(features, list) or len(features) != 11:
        return ["Feature extraction failed or returned unexpected vector length."]

    # Map each feature index to an explanation rule
    # f0: IP in hostname
    if features[0] == 1:
        reasons.append("Hostname is an IP address (possible obfuscation).")

    # f1: URL length
    if features[1] == 1:
        reasons.append("URL is long (length > 75) — common in phishing links.")
    elif features[1] == 0:
        reasons.append("URL length is medium (54–75) — somewhat suspicious.")

    # f2: shortener
    if features[2] == 1:
        reasons.append("URL uses a shortening service (obscures destination).")

    # f3: '@' symbol
    if features[3] == 1:
        reasons.append("URL contains '@' which can hide the real domain.")

    # f4: multiple '//' after protocol
    if features[4] == 1:
        reasons.append("Multiple '//' found in URL path — suspicious structure.")

    # f5: hyphen in hostname
    if features[5] == 1:
        reasons.append("Hyphen found in hostname — may imitate legitimate domains.")

    # f6: subdomain count
    if features[6] == 1:
        reasons.append("Many subdomains detected — may be used to mimic trusted sites.")
    elif features[6] == 0:
        reasons.append("Multiple subdomains present (moderately suspicious).")

    # f7: https
    if features[7] == -1:
        reasons.append("URL is not HTTPS (no TLS) — insecure connection.")

    # f8: suspicious port
    if features[8] == 1:
        reasons.append("Non-standard port used (not 80/443) — unusual setup.")

    # f9: query string
    if features[9] == 1:
        reasons.append("URL contains query parameters — sometimes used in credential-stealing pages.")

    # f10: google hosted
    if features[10] == 1:
        reasons.append("Hosted on Google Sites/Drive — attackers sometimes host phishing content here.")

    # If no reasons found, add short reassurance
    if not reasons:
        reasons.append("No obvious heuristic indicators found.")

    # Optional: add a short summary score (number of positive indicators)
    positive_count = sum(1 for f in features if f == 1)
    reasons.append(f"Detected {positive_count} suspicious indicator(s).")

    return reasons

# ----- Model loading -----
MODEL_PATH = "phishing_rf_model.joblib"
model = None
if os.path.exists(MODEL_PATH):
    try:
        model = joblib.load(MODEL_PATH)
        logger.info(f"Loaded model from {MODEL_PATH}")
    except Exception:
        logger.exception(f"Failed to load model from {MODEL_PATH}")
        model = None
else:
    logger.warning(f"Model file not found at {MODEL_PATH}. Predictions will be unavailable.")

@app.route("/", methods=["GET"])
def index():
    if os.path.exists(os.path.join(app.static_folder, "index.html")):
        return app.send_static_file("index.html")
    return "<h3>Phishing detection API</h3><p>Place a frontend in the <code>static/</code> folder, or POST to /check_phishing.</p>"

@app.route("/check_phishing", methods=["POST"])
def check_phishing():
    if model is None:
        return jsonify({"error": "Model not loaded on server."}), 500

    data = request.get_json(force=True, silent=True)
    if not data:
        return jsonify({"error": "Invalid or missing JSON body"}), 400

    url = data.get("url", "")
    if not isinstance(url, str) or not url.strip():
        return jsonify({"error": "No URL provided"}), 400

    url = url.strip()
    try:
        features = extract_features_from_url(url)
        if not isinstance(features, list) or len(features) != 11:
            logger.error("Feature vector invalid: %r", features)
            return jsonify({"error": "Feature extraction produced invalid output"}), 500

        pred = model.predict([features])[0]
        response = {"isPhishing": bool(pred), "features": features}

        # add probabilities if available
        if hasattr(model, "predict_proba"):
            try:
                proba = model.predict_proba([features])[0].tolist()
                response["probability"] = {"class_0": proba[0], "class_1": proba[1]}
            except Exception:
                logger.exception("predict_proba failed")

        # attach human-readable reasons
        response["reasons"] = reasons_from_features(features, url)

        return jsonify(response)
    except Exception as e:
        logger.exception("Error during prediction")
        return jsonify({"error": f"Failed to process URL: {str(e)}"}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="0.0.0.0", port=port)


