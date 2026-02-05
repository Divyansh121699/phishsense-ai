import os
import json
from datetime import datetime
from dotenv import load_dotenv
from openai import OpenAI
import time

# Load OpenAI API key
load_dotenv()
api_key = os.getenv("OPENAI_API_KEY")
client = OpenAI(api_key=api_key)

# 10 benign categories × 5 variations = 50 emails
benign_scenarios = [
    {"category": "Order Confirmation", "brand": "Amazon", "prompt": "Generate a legitimate Amazon order confirmation email for a recent purchase."},
    {"category": "Newsletter", "brand": "Google", "prompt": "Generate a legitimate monthly Google Workspace newsletter with tips and updates."},
    {"category": "Event Reminder", "brand": "Zoom", "prompt": "Generate a legitimate Zoom event reminder email with meeting link and agenda."},
    {"category": "Password Change Confirmation", "brand": "LinkedIn", "prompt": "Generate a legitimate LinkedIn password change confirmation email."},
    {"category": "Account Activity Alert", "brand": "Microsoft", "prompt": "Generate a legitimate Microsoft email notifying the user of successful sign-in from a new location."},
    {"category": "Shipping Notification", "brand": "FedEx", "prompt": "Generate a legitimate FedEx shipping notification for a package on the way."},
    {"category": "HR Update", "brand": "Internal HR", "prompt": "Generate a legitimate HR email announcing an upcoming company holiday or wellness day."},
    {"category": "Monthly Bill", "brand": "Verizon", "prompt": "Generate a legitimate Verizon monthly bill notification with summary and PDF download link."},
    {"category": "Travel Itinerary", "brand": "Delta Airlines", "prompt": "Generate a legitimate Delta itinerary confirmation with flight details and check-in link."},
    {"category": "Subscription Renewal", "brand": "Spotify", "prompt": "Generate a legitimate Spotify Premium renewal confirmation email with billing details."}
]

# Output folder
BENIGN_DIR = "benign_emails"
os.makedirs(BENIGN_DIR, exist_ok=True)

# Loop through scenarios and generate 5 emails each
for scenario in benign_scenarios:
    for i in range(5):
        print(f"✉️ Generating: {scenario['category']} - {scenario['brand']} (v{i+1}/5)")

        try:
            response = client.chat.completions.create(
                model="gpt-3.5-turbo",
                messages=[{"role": "user", "content": f"{scenario['prompt']} Make this variation realistic and professional. (version {i+1})"}],
                temperature=0.7,
                max_tokens=350
            )

            email_text = response.choices[0].message.content

            email_metadata = {
                "timestamp": datetime.now().isoformat(),
                "category": scenario["category"],
                "brand": scenario["brand"],
                "source_model": "gpt-3.5-turbo",
                "variation": i + 1,
                "email_text": email_text
            }

            filename = f"{scenario['category'].replace(' ', '_').lower()}_{scenario['brand'].replace(' ', '_').lower()}_v{i+1}_{datetime.now().strftime('%Y%m%d_%H%M%S_%f')}.json"
            filepath = os.path.join(BENIGN_DIR, filename)

            with open(filepath, "w", encoding="utf-8") as f:
                json.dump(email_metadata, f, indent=4)

            print(f"✅ Saved to: {filepath}\n")
            time.sleep(1.2)

        except Exception as e:
            print(f"❌ Error generating email: {str(e)}\n")
            time.sleep(2)
