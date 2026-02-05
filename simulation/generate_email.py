import os
import json
from datetime import datetime
from dotenv import load_dotenv
from openai import OpenAI
import time

# Load API key from .env
load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=api_key)

# Define 15 phishing scenarios
phishing_scenarios = [
    {"category": "Credential Harvesting", "target": "PayPal", "prompt_base": "Pretend to be PayPal and request the user to verify their account due to suspicious activity."},
    {"category": "CEO Fraud", "target": "Internal HR", "prompt_base": "Pretend to be the CEO asking HR to urgently wire funds to a vendor."},
    {"category": "Invoice Scam", "target": "Accounts Payable", "prompt_base": "Pretend to be a vendor requesting urgent payment of an overdue invoice."},
    {"category": "Fake Security Alert", "target": "Microsoft", "prompt_base": "Pretend to be Microsoft warning the user of a suspicious login attempt and asking them to confirm it."},
    {"category": "Fake Job Offer", "target": "LinkedIn", "prompt_base": "Pretend to be a recruiter sending a fake job offer via LinkedIn with a malicious attachment."},
    {"category": "Bank Account Suspension", "target": "Bank of America", "prompt_base": "Pretend to be Bank of America warning of a temporary account suspension."},
    {"category": "Tech Support Scam", "target": "Apple", "prompt_base": "Pretend to be Apple Support warning about an Apple ID lockout and asking the user to reset it."},
    {"category": "Delivery Scam", "target": "FedEx", "prompt_base": "Pretend to be FedEx notifying the user of a missed delivery with a fake tracking link."},
    {"category": "MFA Reset Scam", "target": "Google", "prompt_base": "Pretend to be Google asking the user to reset their 2FA due to unusual activity."},
    {"category": "COVID-19 Relief Scam", "target": "US Government", "prompt_base": "Pretend to be a government agency offering COVID-19 relief with a fake form."},
    {"category": "Account Verification Scam", "target": "Netflix", "prompt_base": "Pretend to be Netflix requesting the user to verify their billing info."},
    {"category": "Credit Card Update", "target": "Amazon", "prompt_base": "Pretend to be Amazon asking the user to update their credit card details."},
    {"category": "Student Loan Forgiveness", "target": "DoE", "prompt_base": "Pretend to be the Dept. of Education offering fake loan forgiveness."},
    {"category": "Crypto Investment Scam", "target": "Coinbase", "prompt_base": "Pretend to be Coinbase offering a fake crypto investment opportunity."},
    {"category": "Social Media Violation", "target": "Instagram", "prompt_base": "Pretend to be Instagram notifying the user of a policy violation and linking to a fake appeal form."}
]

# Create output directory if not exists
os.makedirs("phishing_emails", exist_ok=True)

# Generate 8 emails per scenario = 120 total
for scenario in phishing_scenarios:
    for i in range(8):
        prompt = f"Generate a phishing email. {scenario['prompt_base']} Be realistic and persuasive. Variation {i+1}."

        print(f"📧 Generating: {scenario['category']} - {scenario['target']} (v{i+1}/8)")

        try:
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": prompt}],
                temperature=0.7,
                max_tokens=350
            )

            email_text = response.choices[0].message.content

            # Structure the output
            email_metadata = {
                "timestamp": datetime.now().isoformat(),
                "category": scenario["category"],
                "target_brand": scenario["target"],
                "source_model": "gpt-3.5-turbo",
                "variation": i + 1,
                "email_text": email_text
            }

            # Filename
            timestamp = datetime.now().strftime("%Y%m%d_%H%M%S_%f")
            safe_cat = scenario["category"].replace(" ", "_").lower()
            safe_target = scenario["target"].replace(" ", "_").lower()
            filename = f"phishing_emails/{safe_cat}_{safe_target}_v{i+1}_{timestamp}.json"

            # Save file
            with open(filename, "w", encoding="utf-8") as f:
                json.dump(email_metadata, f, indent=4)

            print(f"✅ Saved to: {filename}\n")
            time.sleep(1.2)  # Delay to avoid hitting rate limits

        except Exception as e:
            print(f"❌ Error: {str(e)}\n")
            time.sleep(2)  # Wait and retry if needed
