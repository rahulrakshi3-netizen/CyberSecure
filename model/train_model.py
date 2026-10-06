import pandas as pd
import numpy as np
from sklearn.ensemble import RandomForestClassifier
from sklearn.model_selection import train_test_split
import joblib
import os

# Create a synthetic dataset for demonstration purposes
# Features: url_length, has_special_chars, num_subdomains, is_https, has_suspicious_keywords
data = {
    'url_length': [25, 150, 45, 80, 200, 30, 120, 50, 60, 250],
    'has_special_chars': [0, 1, 0, 1, 1, 0, 1, 0, 0, 1],
    'num_subdomains': [1, 4, 2, 3, 5, 1, 4, 2, 1, 6],
    'is_https': [1, 0, 1, 1, 0, 1, 0, 1, 1, 0],
    'has_suspicious_keywords': [0, 1, 0, 1, 1, 0, 1, 0, 0, 1],
    'is_phishing': [0, 1, 0, 1, 1, 0, 1, 0, 0, 1] # Target
}

df = pd.DataFrame(data)

X = df.drop('is_phishing', axis=1)
y = df['is_phishing']

X_train, X_test, y_train, y_test = train_test_split(X, y, test_size=0.2, random_state=42)

model = RandomForestClassifier(n_estimators=100, random_state=42)
model.fit(X_train, y_train)

# Save the model
model_path = os.path.join(os.path.dirname(__file__), 'phishing_model.pkl')
joblib.dump(model, model_path)
print(f"Model saved to {model_path}")
