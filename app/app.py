import streamlit as st
import json
from utils import run_combined_detection

st.set_page_config(page_title="PhishSense AI", layout="wide")
st.title("📧 PhishSense AI - Hybrid Email Detection")

tab1, tab2 = st.tabs(["✍️ Generate Email", "🔍 Detect Phishing"])

with tab1:
    st.subheader("Generate Sample Email")
    type_choice = st.selectbox("Select Email Type", ["Phishing", "Benign"])
    theme = st.selectbox("Choose a Theme", ["Bank", "Job Offer", "Invoice", "CEO Scam", "Microsoft", "Other"])

    sample_texts = {
        "Phishing": {
            "Bank": "Dear Customer, please verify your account now to avoid suspension. Click here: http://fakebank.com",
            "Job Offer": "Urgent! You're selected for a remote job at Google. Verify your identity here: http://scamjob.link",
            "Invoice": "Your invoice is overdue. Pay now to avoid penalties: http://payfraud.com",
            "CEO Scam": "I'm the CEO. Wire $5,000 now for confidential acquisition.",
            "Microsoft": "Security alert: Login attempt detected. Reset password: http://microsoft-login.xyz"
        },
        "Benign": {
            "Bank": "Your statement is ready. Visit your bank's official app to view it.",
            "Job Offer": "Thanks for applying. We’ll get back to you after reviewing your resume.",
            "Invoice": "Please find attached invoice for your recent order. Pay by next week.",
            "CEO Scam": "Weekly update from the CEO on our Q2 results. No actions needed.",
            "Microsoft": "Your Office 365 subscription has been renewed successfully."
        }
    }

    email_text = sample_texts[type_choice][theme]
    st.text_area("Generated Email", value=email_text, height=250)

with tab2:
    st.subheader("Paste or Upload Email for Detection")

    uploaded_file = st.file_uploader("Upload email JSON", type="json")
    text_input = st.text_area("Or paste raw email text here")

    if st.button("Run Detection"):
        if uploaded_file:
            data = json.load(uploaded_file)
            email_text = data.get("email_text", "")
        elif text_input:
            data = {"email_text": text_input}
            email_text = text_input
        else:
            st.error("Please upload or paste an email first.")
            st.stop()

        results = run_combined_detection(email_text, data)

        st.markdown(f"### 🤖 **LLM Prediction:** `{results['llm_label']}`")
        st.markdown(f"#### 💬 Explanation:\n```\n{results['llm_explanation']}\n```")
        st.markdown(f"### 🛠 **Rule-Based Score:** `{results['rule_result']['score']}`")
        st.markdown(f"#### 🔍 Triggered Rules: {results['rule_result']['flagged_keywords']}")
        st.success(f"🧾 **Final Hybrid Decision:** `{results['hybrid_label'].upper()}`")
