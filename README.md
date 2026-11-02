# Phishing Website Detector — Streamlit

## Files
- `app.py`: Streamlit interface and feature extraction
- `phishing_model_24.pkl`: your trained model
- `requirements.txt`: Python dependencies

## Run locally
1. Install Python 3.10 or 3.11.
2. Open a terminal in this folder.
3. Install dependencies:
   `pip install -r requirements.txt`
4. Start the app:
   `streamlit run app.py`

## Important notes
- The app expects all 24 model features in the same order as the trained model.
- Some features cannot be reliably determined without WHOIS or richer page analysis, so the app uses neutral values for some of them.
- Confirm the model's class labels from your training dataset. The sidebar defaults to class `-1` = phishing and class `1` = legitimate, a common convention for this dataset family.
- A prediction is not a security guarantee. Avoid entering credentials on suspicious sites.
