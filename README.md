Phishing Website Detector

Overview

The Phishing Website Detector is a machine learning-based cybersecurity application designed to identify potentially malicious and legitimate websites by analyzing URL patterns and website characteristics. Developed using Python, Scikit-learn, and Streamlit, the application provides an interactive dashboard that allows users to enter a website URL and receive a prediction about its potential phishing risk.

The system uses a trained Decision Tree Classifier that analyzes 24 website-related features to generate predictions. By combining machine learning with an intuitive user interface, the project demonstrates how data-driven techniques can support phishing detection and improve awareness of web security threats.

Key Features

- URL-Based Detection: Accepts website URLs for phishing risk assessment.
- Machine Learning Classification: Uses a trained Decision Tree Classifier to categorize websites based on extracted features.
- 24-Feature Analysis: Evaluates website characteristics such as URL length, IP address usage, HTTPS availability, domain registration length, URL redirection, and iframe redirection.
- Interactive Dashboard: Provides a user-friendly Streamlit interface for submitting URLs and viewing prediction results.
- Prediction Visualization: Displays classification results and model probability estimates where available.
- Feature Inspection: Presents extracted website features to help users understand the information used for classification.
- Scan History: Displays recent scans during the current application session.
- Real-Time Website Inspection: Attempts to retrieve website information and extract relevant features for analysis.

Technology Stack

- Programming Language: Python
- Machine Learning: Scikit-learn
- Classification Algorithm: Decision Tree Classifier
- Frontend and Dashboard: Streamlit
- Website Data Extraction: Requests and BeautifulSoup
- Model Storage: Pickle (`.pkl`)

How It Works

1. URL Input: The user enters the URL of the website to be inspected.
2. Website Inspection: The application attempts to retrieve website information and examine relevant characteristics.
3. Feature Extraction: The application extracts or estimates the website features required by the trained model.
4. Model Prediction: The extracted features are passed to the Decision Tree Classifier.
5. Result Display: The dashboard displays the predicted classification, available probability estimates, and feature information.

Model Features

The classifier uses 24 features associated with website and URL characteristics, including:

- IP address usage
- URL length
- URL shortening services
- Special character usage (`@`)
- URL redirection patterns
- Prefix and suffix usage in domain names
- Number of subdomains
- HTTPS availability
- Domain registration length
- Favicon characteristics
- Non-standard port usage
- HTTPS token usage in the domain
- External resource requests
- Anchor URL characteristics
- Links in script and link tags
- Server form handler characteristics
- Email information
- Abnormal URL characteristics
- Website forwarding behavior
- Status bar customization
- Right-click disabling
- Popup window usage
- Iframe redirection
- DNS recording information

Installation and Setup

Prerequisites

- Python 3.9 or later
- pip package manager
- Git

Installation

1. Clone the repository:

   `git clone https://github.com/PoornaKG/Phishing-Website-Detector.git`

2. Navigate to the project directory:

   `cd Phishing-Website-Detector`

3. Install the required dependencies:

   `pip install -r requirements.txt`

4. Run the Streamlit application:

   `streamlit run app.py`

5. Open the local URL displayed in the terminal, typically `http://localhost:8501`.

Project Objective

The objective of this project is to demonstrate the practical application of machine learning in cybersecurity by developing an interactive tool for identifying potentially suspicious websites. It combines website feature analysis, supervised classification, and an accessible dashboard in a single application.

Limitations

- Predictions depend on the quality of the trained model and the features extracted by the application.
- Some website characteristics may be estimated when they cannot be directly retrieved.
- Website behavior can change over time, which may affect feature extraction and predictions.
- A classification result is not a guarantee that a website is safe or malicious.
- Model performance should be assessed using appropriate evaluation metrics and a representative test dataset.

 Future Enhancements

- Evaluate model performance using accuracy, precision, recall, F1-score, and a confusion matrix.
- Improve feature extraction and align it with the original training dataset.
- Compare Decision Tree performance with algorithms such as Random Forest and XGBoost.
- Add prediction history and downloadable scan reports.
- Deploy the application to a cloud hosting platform.
- Enhance URL validation and website inspection security.

Author

Poorna Devi K. G.

GitHub: https://github.com/PoornaKG
