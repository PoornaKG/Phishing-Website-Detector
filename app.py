import ipaddress
import socket
import re
from urllib.parse import urlparse, urljoin

import joblib
import pandas as pd
import requests
import streamlit as st
from bs4 import BeautifulSoup


# -------------------- Page Configuration --------------------

st.set_page_config(
    page_title="Phishing Website Detector",
    page_icon="🛡️",
    layout="wide",
)

MODEL_PATH = "phishing_model_24.pkl"


# -------------------- Model Features --------------------

FEATURES = [
    "UsingIP",
    "LongURL",
    "ShortURL",
    "Symbol@",
    "Redirecting//",
    "PrefixSuffix-",
    "SubDomains",
    "HTTPS",
    "DomainRegLen",
    "Favicon",
    "NonStdPort",
    "HTTPSDomainURL",
    "RequestURL",
    "AnchorURL",
    "LinksInScriptTags",
    "ServerFormHandler",
    "InfoEmail",
    "AbnormalURL",
    "WebsiteForwarding",
    "StatusBarCust",
    "DisableRightClick",
    "UsingPopupWindow",
    "IframeRedirection",
    "DNSRecording",
]


SHORTENERS = {
    "bit.ly",
    "tinyurl.com",
    "t.co",
    "goo.gl",
    "ow.ly",
    "is.gd",
    "buff.ly",
    "adf.ly",
    "cutt.ly",
    "rb.gy",
    "shorturl.at",
    "rebrand.ly",
}


# -------------------- URL Validation --------------------

def safe_public_url(raw_url):
    raw_url = raw_url.strip()

    if not raw_url:
        raise ValueError("Please enter a website URL.")

    if not re.match(r"^https?://", raw_url, flags=re.I):
        raw_url = "https://" + raw_url

    parsed = urlparse(raw_url)

    if parsed.scheme not in ("http", "https") or not parsed.hostname:
        raise ValueError(
            "Enter a valid website URL starting with http:// or https://."
        )

    host = parsed.hostname.lower()

    try:
        addresses = socket.getaddrinfo(host, None)

        for address in addresses:
            ip = ipaddress.ip_address(address[4][0])

            if not ip.is_global:
                raise ValueError(
                    "Private or local network addresses cannot be checked."
                )

    except socket.gaierror:
        # DNS errors will be handled during feature extraction.
        pass
    except OSError:
        pass

    return raw_url, parsed


# -------------------- Helper Functions --------------------

def is_ip_address(host):
    try:
        ipaddress.ip_address(host)
        return True
    except ValueError:
        return False


def host_of(value, base_url):
    """Resolve a URL and return its hostname."""

    try:
        resolved_url = urljoin(base_url, value)
        return (urlparse(resolved_url).hostname or "").lower()

    except (ValueError, TypeError):
        return ""


# -------------------- Feature Extraction --------------------

def analyze_url(raw_url):

    url, parsed = safe_public_url(raw_url)

    host = (parsed.hostname or "").lower()
    port = parsed.port

    features = {}

    # 1. UsingIP
    features["UsingIP"] = (
        -1 if is_ip_address(host) else 1
    )

    # 2. LongURL
    if len(url) > 75:
        features["LongURL"] = -1
    elif len(url) >= 54:
        features["LongURL"] = 0
    else:
        features["LongURL"] = 1

    # 3. ShortURL
    features["ShortURL"] = (
        -1 if host in SHORTENERS else 1
    )

    # 4. Symbol@
    features["Symbol@"] = (
        -1 if "@" in url else 1
    )

    # 5. Redirecting//
    features["Redirecting//"] = (
        -1 if url.find("//", 8) != -1 else 1
    )

    # 6. PrefixSuffix-
    features["PrefixSuffix-"] = (
        -1 if "-" in host else 1
    )

    # 7. SubDomains
    labels = host.split(".")
    subdomain_count = max(0, len(labels) - 2)

    if subdomain_count >= 2:
        features["SubDomains"] = -1
    elif subdomain_count == 1:
        features["SubDomains"] = 0
    else:
        features["SubDomains"] = 1

    # 8. HTTPS
    # This checks the URL scheme, not the validity of its certificate.
    features["HTTPS"] = (
        1 if parsed.scheme.lower() == "https" else -1
    )

    # 9. DomainRegLen
    # Requires domain registration information.
    features["DomainRegLen"] = 0

    # 10. Favicon
    # Initially unknown; may be updated after inspecting the page.
    features["Favicon"] = 0

    # 11. NonStdPort
    features["NonStdPort"] = (
        -1 if port is not None and port not in (80, 443) else 1
    )

    # 12. HTTPSDomainURL
    features["HTTPSDomainURL"] = (
        -1 if "https" in host else 1
    )

    # Features requiring webpage inspection.
    features["RequestURL"] = 0
    features["AnchorURL"] = 0
    features["LinksInScriptTags"] = 0
    features["ServerFormHandler"] = 0
    features["InfoEmail"] = 0
    features["AbnormalURL"] = 0
    features["WebsiteForwarding"] = 0
    features["StatusBarCust"] = 0
    features["DisableRightClick"] = 0
    features["UsingPopupWindow"] = 0
    features["IframeRedirection"] = 0

    # 24. DNSRecording
    try:
        socket.getaddrinfo(host, None)
        features["DNSRecording"] = 1

    except (socket.gaierror, OSError):
        features["DNSRecording"] = -1

    page_status = "Page content not inspected."

    # -------------------- Inspect Webpage --------------------

    try:
        response = requests.get(
            url,
            timeout=8,
            allow_redirects=True,
            headers={
                "User-Agent": (
                    "Mozilla/5.0 "
                    "(compatible; PhishingDetector/1.0)"
                )
            },
        )

        page_status = (
            f"HTTP {response.status_code}; "
            f"final URL: {response.url}"
        )

        soup = BeautifulSoup(
            response.text[:1_000_000],
            "html.parser",
        )

        final_host = (
            urlparse(response.url).hostname or ""
        ).lower()

        html = response.text.lower()

        # 10. Favicon
        icon_tags = [
            tag
            for tag in soup.find_all("link")
            if any(
                "icon" in str(rel).lower()
                for rel in (tag.get("rel") or [])
            )
            and tag.get("href")
        ]

        if icon_tags:
            external_icon = any(
                (icon_host := host_of(
                    tag.get("href"), response.url
                ))
                and icon_host not in (host, final_host)
                for tag in icon_tags
            )

            features["Favicon"] = (
                -1 if external_icon else 1
            )

        # 13. RequestURL
        resources = []

        for tag in soup.find_all(
            ["img", "audio", "video", "source"]
        ):
            src = tag.get("src")

            if src:
                resources.append(
                    host_of(src, response.url)
                )

        external_resources = sum(
            1
            for resource_host in resources
            if resource_host
            and resource_host not in (host, final_host)
        )

        if resources:
            external_ratio = (
                external_resources / len(resources)
            )

            features["RequestURL"] = (
                -1 if external_ratio > 0.5 else 1
            )

        # 14. AnchorURL
        anchors = soup.find_all("a", href=True)

        anchor_hosts = [
            host_of(anchor.get("href"), response.url)
            for anchor in anchors
        ]

        external_anchors = sum(
            1
            for anchor_host in anchor_hosts
            if anchor_host
            and anchor_host not in (host, final_host)
        )

        if anchors:
            anchor_ratio = (
                external_anchors / len(anchors)
            )

            if anchor_ratio > 0.67:
                features["AnchorURL"] = -1
            elif anchor_ratio > 0.33:
                features["AnchorURL"] = 0
            else:
                features["AnchorURL"] = 1

        # 15. LinksInScriptTags
        script_links = []

        for tag in soup.find_all(["script", "link"]):
            value = tag.get("src") or tag.get("href")

            if value:
                script_links.append(
                    host_of(value, response.url)
                )

        external_script_links = sum(
            1
            for script_host in script_links
            if script_host
            and script_host not in (host, final_host)
        )

        if script_links:
            script_ratio = (
                external_script_links / len(script_links)
            )

            features["LinksInScriptTags"] = (
                -1 if script_ratio > 0.5 else 1
            )

        # 16. ServerFormHandler
        forms = soup.find_all("form", action=True)

        if forms:
            external_form = any(
                (form_host := host_of(
                    form.get("action"), response.url
                ))
                and form_host not in (host, final_host)
                for form in forms
            )

            features["ServerFormHandler"] = (
                -1 if external_form else 1
            )

        # 17. InfoEmail
        email_found = (
            "mailto:" in html
            or bool(
                re.search(
                    r"\b[\w.+-]+@[\w.-]+\.[a-z]{2,}\b",
                    html,
                )
            )
        )

        features["InfoEmail"] = (
            -1 if email_found else 1
        )

        # 18. AbnormalURL
        features["AbnormalURL"] = (
            -1
            if final_host and final_host != host
            else 1
        )

        # 19. WebsiteForwarding
        features["WebsiteForwarding"] = (
            -1 if len(response.history) > 1 else 1
        )

        # 20. StatusBarCust
        status_bar_customized = (
            "onmouseover" in html
            and "window.status" in html
        )

        features["StatusBarCust"] = (
            -1 if status_bar_customized else 1
        )

        # 21. DisableRightClick
        right_click_disabled = (
            "contextmenu" in html
            or "event.button==2" in html.replace(" ", "")
        )

        features["DisableRightClick"] = (
            -1 if right_click_disabled else 1
        )

        # 22. UsingPopupWindow
        features["UsingPopupWindow"] = (
            -1 if "window.open(" in html else 1
        )

        # 23. IframeRedirection
        frames = soup.find_all(["iframe", "frame"])

        external_frame = any(
            (frame_host := host_of(
                frame.get("src"), response.url
            ))
            and frame_host not in (host, final_host)
            for frame in frames
        )

        features["IframeRedirection"] = (
            -1 if external_frame else 1
        )

    except requests.RequestException as exc:
        page_status = (
            f"Page fetch failed ({type(exc).__name__}). "
            "Some features remain unknown (0)."
        )

    # -------------------- Arrange Features --------------------

    # Maintain the exact order expected by the trained model.
    values = [
        features[name]
        for name in FEATURES
    ]

    if len(values) != 24:
        raise RuntimeError(
            f"Expected 24 features, but got {len(values)}."
        )

    return url, features, values, page_status


# -------------------- Load Trained Model --------------------

@st.cache_resource
def load_model():

    model = joblib.load(MODEL_PATH)

    if getattr(model, "n_features_in_", None) != len(FEATURES):
        raise RuntimeError(
            f"The model expects "
            f"{getattr(model, 'n_features_in_', 'unknown')} "
            f"features, but the application supplies "
            f"{len(FEATURES)}."
        )

    model_names = list(
        getattr(model, "feature_names_in_", [])
    )

    if model_names and model_names != FEATURES:
        raise RuntimeError(
            "The feature names or order in app.py do not "
            "match the saved model. Check the FEATURES list."
        )

    return model


# -------------------- Streamlit Interface --------------------

st.title("🛡️ Phishing Website Detector")

st.write(
    "Check a website URL using your trained "
    "Decision Tree machine-learning model."
)

st.info(
    "This application uses your saved 24-feature model. "
    "Some features are approximated, and unavailable features "
    "may be set to 0. A prediction is a screening signal, "
    "not proof that a website is safe."
)


# -------------------- Sidebar Settings --------------------

with st.sidebar:

    st.header("Model Settings")

    st.warning(
        "Verify the class meanings using your original "
        "training dataset. The default below assumes "
        "-1 = phishing and 1 = legitimate, but this "
        "has not yet been confirmed."
    )

    phishing_label = st.selectbox(
        "Class representing phishing",
        options=[-1, 1],
        index=0,
    )

    legitimate_label = (
        1 if phishing_label == -1 else -1
    )

    st.write(
        "Class representing legitimate: "
        f"**{legitimate_label}**"
    )

    st.divider()

    st.caption(
        "Keep phishing_model_24.pkl in the same folder "
        "as app.py."
    )


# -------------------- URL Input --------------------

url_input = st.text_input(
    "Website URL",
    placeholder="https://example.com",
    help="Enter a complete URL or a domain name.",
)

check = st.button(
    "Check Website",
    type="primary",
    use_container_width=True,
)


# -------------------- Prediction --------------------

if check:

    if not url_input.strip():

        st.warning("Please enter a website URL.")

    else:

        try:

            with st.spinner(
                "Analyzing the URL and available webpage features..."
            ):

                model = load_model()

                (
                    normalized_url,
                    feature_dict,
                    values,
                    page_status,
                ) = analyze_url(url_input)

                # Use a DataFrame with named columns when
                # the model was trained with feature names.
                if hasattr(model, "feature_names_in_"):

                    model_input = pd.DataFrame(
                        [values],
                        columns=FEATURES,
                    )

                else:

                    model_input = [values]

                prediction = int(
                    model.predict(model_input)[0]
                )

                probabilities = None

                if hasattr(model, "predict_proba"):

                    probabilities = model.predict_proba(
                        model_input
                    )[0]

            # -------------------- Display Results --------------------

            st.subheader("Result")

            st.write(
                f"**Checked URL:** {normalized_url}"
            )

            st.write(
                f"**Page inspection:** {page_status}"
            )

            if prediction == phishing_label:

                st.error(
                    "⚠️ Potential phishing website"
                )

            elif prediction == legitimate_label:

                st.success(
                    "✅ Likely legitimate website"
                )

            else:

                st.warning(
                    f"Model returned class {prediction}"
                )

            # -------------------- Model Probabilities --------------------

            if probabilities is not None:

                st.subheader("Model Output")

                probability_df = pd.DataFrame(
                    {
                        "Model class": list(model.classes_),
                        "Model probability (%)": [
                            round(float(probability) * 100, 2)
                            for probability in probabilities
                        ],
                    }
                )

                st.dataframe(
                    probability_df,
                    use_container_width=True,
                    hide_index=True,
                )

                st.caption(
                    "These probabilities reflect the model's "
                    "output and are not a guarantee of safety."
                )

            # -------------------- Feature Details --------------------

            with st.expander(
                "View the 24 features sent to the model"
            ):

                meanings = [
                    "Hostname is an IP address",
                    "URL length category",
                    "Known URL shortener",
                    "@ symbol in URL",
                    "Extra // after the scheme",
                    "Hyphen in hostname",
                    "Subdomain count category",
                    "URL uses HTTPS; certificate not verified",
                    "Domain registration length; unknown",
                    "Favicon host signal; may be unknown",
                    "Non-standard port",
                    "HTTPS text appears in hostname",
                    "External resource ratio",
                    "External anchor ratio",
                    "External script/link ratio",
                    "Form action host signal",
                    "Email/contact pattern",
                    "Final hostname differs from entered hostname",
                    "Multiple redirects",
                    "Status-bar manipulation pattern",
                    "Right-click disabling pattern",
                    "Popup pattern",
                    "External iframe pattern",
                    "DNS lookup succeeded",
                ]

                feature_df = pd.DataFrame(
                    {
                        "Feature": FEATURES,
                        "Value": values,
                        "Meaning": meanings,
                    }
                )

                st.dataframe(
                    feature_df,
                    use_container_width=True,
                    hide_index=True,
                )

        except ValueError as exc:

            st.error(str(exc))

        except FileNotFoundError:

            st.error(
                f"Model file not found. Place "
                f"{MODEL_PATH} in the same folder as app.py."
            )

        except Exception as exc:

            st.error(
                f"Prediction failed: "
                f"{type(exc).__name__}: {exc}"
            )


# -------------------- Footer --------------------

st.divider()

st.caption(
    "For important decisions, verify suspicious links independently. "
    "Never enter passwords or payment details on a website you do not trust."
)