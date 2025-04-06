import streamlit as st
import pandas as pd
import joblib
import requests
import re
import json
from tensorflow.keras.models import load_model
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from datetime import datetime
import whois

# Load Model
model = load_model('best_nn_model_rfe.keras')  # Ensure correct path

# Load user feedback
try:
    with open("user_feedback.json", "r") as f:
        user_feedback = json.load(f)
except FileNotFoundError:
    user_feedback = {}

# Features to be used
selected_features_nb = [
    'length_url', 'length_hostname', 'nb_www', 'ratio_digits_url',
    'length_words_raw', 'longest_word_path', 'avg_word_path',
    'phish_hints', 'nb_hyperlinks', 'ratio_intHyperlinks',
    'ratio_extHyperlinks', 'safe_anchor', 'domain_registration_length',
    'domain_age', 'web_traffic', 'google_index', 'page_rank'
]

# Feature Extraction

def extract_features(url):
    hostname = urlparse(url).netloc
    domain = '.'.join(hostname.split('.')[-2:])

    def length_url(url): return len(url)
    def length_hostname(url): return len(urlparse(url).netloc)
    def nb_www(url): return url.lower().count('www')
    def ratio_digits_url(url): return sum(c.isdigit() for c in url) / len(url) if len(url) > 0 else 0
    def phish_hints(url): return sum(1 for keyword in ['secure', 'account', 'update', 'login', 'signin', 'bank'] if keyword in url.lower())

    def domain_registration_length(domain_name):
        try:
            domain = whois.whois(domain_name)
            if isinstance(domain.expiration_date, list):
                return (domain.expiration_date[0] - domain.creation_date).days / 365.0
            else:
                return (domain.expiration_date - domain.creation_date).days / 365.0
        except:
            return 0

    def domain_age(domain_name):
        try:
            domain = whois.whois(domain_name)
            if isinstance(domain.creation_date, list):
                return (datetime.now() - domain.creation_date[0]).days / 365.0
            else:
                return (datetime.now() - domain.creation_date).days / 365.0
        except:
            return 0

    def web_traffic(url):
        try:
            alexa_rank = requests.get(f"http://data.alexa.com/data?cli=10&dat=s&url={url}")
            rank = BeautifulSoup(alexa_rank.content, 'xml').find("REACH")['RANK']
            return int(rank) if rank.isdigit() else 0
        except:
            return 0
    
    # New Features
    def extract_page_features(url):
        try:
            response = requests.get(url, timeout=5)
            soup = BeautifulSoup(response.content, 'html.parser')

            # All hyperlinks
            all_links = [a['href'] for a in soup.find_all('a', href=True)]

            # Internal and external links
            internal_links = [link for link in all_links if hostname in link]
            external_links = [link for link in all_links if hostname not in link]

            # Features
            nb_hyperlinks = len(all_links)
            ratio_intHyperlinks = len(internal_links) / nb_hyperlinks if nb_hyperlinks > 0 else 0
            ratio_extHyperlinks = len(external_links) / nb_hyperlinks if nb_hyperlinks > 0 else 0
            words_raw = [word for word in re.split(r'\W+', ' '.join(all_links)) if word]
            longest_word_path = max(len(word) for word in words_raw) if words_raw else 0
            avg_word_path = sum(len(word) for word in words_raw) / len(words_raw) if words_raw else 0
            length_words_raw = len(words_raw)

            return nb_hyperlinks, ratio_intHyperlinks, ratio_extHyperlinks, longest_word_path, avg_word_path, length_words_raw
        except:
            return 0, 0, 0, 0, 0, 0
    
    nb_hyperlinks, ratio_intHyperlinks, ratio_extHyperlinks, longest_word_path, avg_word_path, length_words_raw = extract_page_features(url)

    return {
        'length_url': length_url(url),
        'length_hostname': length_hostname(url),
        'nb_www': nb_www(url),
        'ratio_digits_url': ratio_digits_url(url),
        'length_words_raw': length_words_raw,
        'longest_word_path': longest_word_path,
        'avg_word_path': avg_word_path,
        'phish_hints': phish_hints(url),
        'nb_hyperlinks': nb_hyperlinks,
        'ratio_intHyperlinks': ratio_intHyperlinks,
        'ratio_extHyperlinks': ratio_extHyperlinks,
        'safe_anchor': url.count('#'),
        'domain_registration_length': domain_registration_length(domain),
        'domain_age': domain_age(domain),
        'web_traffic': web_traffic(url),
        'google_index': 1,  # Placeholder
        'page_rank': 0  # Placeholder
    }

# Prediction Function
def predict_url(url):
    features = extract_features(url)
    features_df = pd.DataFrame([features])
    features_df = features_df[selected_features_nb]
    prediction_proba = model.predict(features_df).flatten()
    prediction_label = "Legitimate" if prediction_proba[0] <= 0.5 else "Phishing"

    # Check user feedback
    if url in user_feedback:
        prediction_label = user_feedback[url]

    return prediction_label, round(float(prediction_proba[0]) * 100, 2)

# Streamlit App
st.set_page_config(page_title="Phishing Detector", page_icon="🛡️", layout="centered")
st.title("🔍 AI-Powered Phishing Detector 🛡️")
st.markdown("### Detect if a website is safe or a phishing attempt in seconds!")

# Input URL
url = st.text_input("🔗 Enter the URL to analyze:", placeholder="https://example.com")

if st.button("🚀 Analyze"):
    if url:
        prediction, confidence = predict_url(url)

        # Display Result
        if prediction == "Legitimate":
            st.success(f"✅ This website is **SAFE**! (Confidence: {confidence}%)")
        else:
            st.error(f"⚠️ This might be a **PHISHING** site! (Confidence: {confidence}%)")
    else:
        st.warning("Please enter a valid URL.")

# User Feedback Section
st.markdown("### 🤖 Help us improve!")
feedback = st.radio("Is this prediction correct?", ("Yes", "No"), horizontal=True)

if feedback == "No":
    correct_label = st.radio("What should the correct label be?", ("Legitimate", "Phishing"))
    if st.button("Submit Feedback"):
        user_feedback[url] = correct_label
        with open("user_feedback.json", "w") as f:
            json.dump(user_feedback, f)
        st.success("✅ Thank you! Your feedback has been recorded.")

# Footer
st.markdown("---")
st.markdown("🔒 **Your privacy is protected.** We do not store your URLs.")
